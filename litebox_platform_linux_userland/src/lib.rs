// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.
//!
//! The guest shares the host process's address space, so this platform does not isolate host
//! memory from the guest: guest code or fixed-address mappings can read or overwrite it.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86/x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::cell::Cell;
use std::io::IsTerminal as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;
use std::unimplemented;

use litebox::fs::OFlags;
use litebox::platform::ImmediatelyWokenUp;
use litebox::platform::UnblockedOrTimedOut;
use litebox::platform::page_mgmt::{
    CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, vmap::VmapManager};

use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

mod page_mgmt;
mod x86_64;
#[doc(hidden)]
pub use page_mgmt::LinuxUserlandReservation;
use x86_64::{
    GUEST_XSTATE, GuestXstateInit, activate_xstate, copy_signal_context, run_thread_arch,
    saved_tls, saved_tls_seg, set_signal_return, signal_handler_exit_guest, switch_to_guest, tls,
    tls_seg, tls_suffix,
};

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    tun_socket_fd: std::sync::RwLock<Option<std::os::fd::OwnedFd>>,
    /// CoW-eligible memory regions. Maps start address of the static slice, to the info needed to
    /// re-mmap the file.
    cow_regions: std::sync::RwLock<std::collections::BTreeMap<usize, CowRegionInfo>>,
    /// If [`Self::initialize_boot_specific_kdf_support`] has been run, this is set to a value that
    /// is persistent across multiple process executions, however, it is ephemeral across true
    /// reboots.
    boot_id: std::sync::OnceLock<Vec<u8>>,
    stdio_is_tty: [bool; 3],
}

impl core::fmt::Debug for LinuxUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxUserland").finish_non_exhaustive()
    }
}

/// Information about a CoW-eligible memory region backed by a file.
#[derive(Debug, Clone)]
struct CowRegionInfo {
    /// The path to the backing file on the host filesystem.
    file_path: PathBuf,
    /// Length of the backing file.
    file_length: usize,
}

const IF_NAMESIZE: usize = 16;
/// Use TUN device
const IFF_TUN: i32 = 0x0001;
/// Do not provide packet information
const IFF_NO_PI: i32 = 0x1000;
/// libc `ifreq` structure, used for TUN/TAP devices.
#[repr(C)]
struct Ifreq {
    /// interface name, e.g. "en0"
    pub ifr_name: [i8; IF_NAMESIZE],
    pub ifr_ifru: Ifru,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ifmap {
    mem_start: usize,
    mem_end: usize,
    base_addr: u16,
    irq: u8,
    dma: u8,
    port: u8,
}

/// libc `ifreq.ifr_ifru` union, used for TUN/TAP devices.
///
/// We only need `ifru_flags` for now; `ifru_map` is to ensure the size of the union
/// matches libc.
#[repr(C)]
pub union Ifru {
    // pub ifru_addr: crate::sockaddr,
    // pub ifru_dstaddr: crate::sockaddr,
    // pub ifru_broadaddr: crate::sockaddr,
    // pub ifru_netmask: crate::sockaddr,
    // pub ifru_hwaddr: crate::sockaddr,
    ifru_flags: i16,
    // pub ifru_ifindex: i32,
    // pub ifru_metric: i32,
    // pub ifru_mtu: i32,
    ifru_map: Ifmap,
    // pub ifru_slave: [i8; IF_NAMESIZE],
    // pub ifru_newname: [i8; IF_NAMESIZE],
    // pub ifru_data: *mut i8,
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
        register_exception_handlers();

        let tun_socket_fd = tun_device_name
            .map(|tun_device_name| {
                let tun_path = b"/dev/net/tun\0";
                let tun_fd = unsafe {
                    syscalls::syscall3(
                        syscalls::Sysno::open,
                        tun_path.as_ptr() as usize,
                        (litebox::fs::OFlags::RDWR
                            | litebox::fs::OFlags::CLOEXEC
                            | litebox::fs::OFlags::NONBLOCK)
                            .bits() as usize,
                        litebox::fs::Mode::empty().bits() as usize,
                    )
                }
                .expect("failed to open tun device");

                let tunsetiff = |fd: usize, ifreq: *const Ifreq| {
                    let cmd =
                        litebox_common_linux::iow!(b'T', 202, size_of::<::core::ffi::c_int>());
                    unsafe {
                        syscalls::syscall3(syscalls::Sysno::ioctl, fd, cmd as usize, ifreq as usize)
                    }
                    .expect("failed to set TUN interface flags");
                };
                let ifreq = Ifreq {
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
                    ifr_ifru: Ifru {
                        // IFF_NO_PI: no tun header
                        // IFF_TUN: create tun (i.e., IP)
                        ifru_flags: i16::try_from(IFF_TUN | IFF_NO_PI).unwrap(),
                    },
                };
                tunsetiff(tun_fd, &raw const ifreq);

                // By taking ownership, we are letting the drop handler automatically run `libc::close`
                // when necessary.
                unsafe { std::os::fd::OwnedFd::from_raw_fd(tun_fd.reinterpret_as_signed().trunc()) }
            })
            .into();

        let platform = Self {
            tun_socket_fd,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            boot_id: std::sync::OnceLock::new(),
            stdio_is_tty: [
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
                std::io::stderr().is_terminal(),
            ],
        };
        Box::leak(Box::new(platform))
    }

    /// Initializes support for KDFs by using boot-specific uniqueness.
    ///
    /// NOTE: The boot-specific uniqueness is NOT secure against an adversary with code execution or
    /// file read permissions on the host file system, since other processes on the same system can
    /// also derive the exact same keys.
    ///
    /// # Panics
    ///
    /// Panics if some standard Linux kernel-provided files are not available/accessible.
    ///
    /// Panics if run more than once on the same platform instance.
    pub fn initialize_boot_specific_kdf_support(&self) {
        let parsed: Vec<u8> = std::fs::read("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim_ascii()
            .split(|&x| x == b'-')
            .flat_map(|chunk| {
                chunk
                    .chunks(2)
                    .map(|t| u8::from_str_radix(str::from_utf8(t).unwrap(), 16).unwrap())
            })
            .collect();
        assert_eq!(parsed.len(), 16);
        self.boot_id.set(parsed).unwrap();
    }

    /// Register a CoW-eligible memory region backed by a file.
    ///
    /// # Panics
    ///
    /// Panics if an overlapping region is already registered.
    pub fn register_cow_region(&self, data: &'static [u8], file_path: impl Into<PathBuf>) {
        let start = data.as_ptr() as usize;
        let info = CowRegionInfo {
            file_path: file_path.into(),
            file_length: data.len(),
        };

        let mut regions = self.cow_regions.write().unwrap();
        assert!(
            regions.range(start..start + data.len()).next().is_none(),
            "Attempting to register an overlapping region"
        );
        let old = regions.insert(start, info);
        assert!(old.is_none());
    }

    /// Look up the file backing a static slice for CoW mapping.
    ///
    /// Returns `Some((file_path, offset_in_file))` if the slice is backed by a registered
    /// CoW region, `None` otherwise.
    fn lookup_cow_region(&self, source_data: &'static [u8]) -> Option<(PathBuf, usize)> {
        let slice_start = source_data.as_ptr() as usize;
        let slice_len = source_data.len();

        let regions = self.cow_regions.read().unwrap();

        if let Some((&region_start, info)) = regions.range(..=slice_start).next_back() {
            let region_end = region_start.checked_add(info.file_length).unwrap();
            let slice_end = slice_start.checked_add(slice_len).unwrap();

            if slice_start >= region_start && slice_end <= region_end {
                return Some((info.file_path.clone(), slice_start - region_start));
            }
        }
        None
    }

    #[expect(
        clippy::missing_panics_doc,
        reason = "panicking only on failures of documented linux contracts"
    )]
    pub fn init_task(&self) -> litebox_common_linux::TaskParams {
        let tid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::gettid) }
            .try_into()
            .unwrap();
        let ppid = unsafe { syscalls::raw::syscall0(syscalls::Sysno::getppid) }
            .try_into()
            .unwrap();
        litebox_common_linux::TaskParams {
            pid: tid,
            ppid,
            uid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getuid) }
                .try_into()
                .unwrap(),
            euid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::geteuid) }
                .try_into()
                .unwrap(),
            gid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getgid) }
                .try_into()
                .unwrap(),
            egid: unsafe { syscalls::raw::syscall0(syscalls::Sysno::getegid) }
                .try_into()
                .unwrap(),
        }
    }

    /// Wait until there is data available on the TUN device.
    ///
    /// # Panics
    ///
    /// Panics if the TUN device is not initialized.
    pub fn wait_on_tun(&self, timeout: Option<Duration>) {
        let tun_fd = self.tun_socket_fd.read().unwrap();
        let mut pfd = libc::pollfd {
            fd: tun_fd.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let _ = unsafe {
            libc::poll(
                &raw mut pfd,
                1,
                timeout.map_or(-1, |t| {
                    let ms = t.as_millis();
                    i32::try_from(ms).unwrap_or(i32::MAX)
                }),
            )
        };
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(
        clippy::missing_panics_doc,
        reason = "the seccomp filter rules are hardcoded and not expected to fail"
    )]
    pub fn enable_seccomp_filter() {
        use seccompiler::{
            BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
            SeccompFilter, SeccompRule,
        };

        let rules = vec![
            // TUN and terminal
            (libc::SYS_read, vec![]),
            (libc::SYS_write, vec![]),
            (libc::SYS_poll, vec![]),
            // memory management
            (libc::SYS_mmap, vec![]),
            (libc::SYS_mprotect, vec![]),
            (libc::SYS_munmap, vec![]),
            (libc::SYS_mremap, vec![]),
            // signal
            (libc::SYS_rt_sigreturn, vec![]),
            (libc::SYS_sigaltstack, vec![]),
            (libc::SYS_tgkill, vec![]),
            (libc::SYS_timer_create, vec![]),
            (libc::SYS_timer_settime, vec![]),
            (libc::SYS_timer_delete, vec![]),
            // called by [pthread_create](https://codebrowser.dev/glibc/glibc/nptl/pthread_create.c.html#83) to set up signal handler
            // to support setuid et.al. functions (which we probably don't need, but include them in debug mode to suppress the warnings
            // about missing seccomp rules for these syscalls).
            #[cfg(debug_assertions)]
            (libc::SYS_rt_sigaction, vec![]),
            // TODO: also called by `next_signal_handler`, but I'm not sure if it's really needed.
            (libc::SYS_rt_sigprocmask, vec![]),
            // thread management
            (libc::SYS_exit, vec![]),
            (libc::SYS_exit_group, vec![]),
            (libc::SYS_clone3, vec![]),
            // sync
            (libc::SYS_futex, vec![]),
            // misc
            (libc::SYS_getrandom, vec![]),
            // required by std spawn
            (libc::SYS_rseq, vec![]),
            (libc::SYS_set_robust_list, vec![]),
            (libc::SYS_get_robust_list, vec![]),
            (libc::SYS_sched_getaffinity, vec![]),
            (libc::SYS_gettid, vec![]),
            (libc::SYS_madvise, vec![]),
            // required by libc allocator
            (libc::SYS_brk, vec![]),
            (libc::SYS_getpid, vec![]),
            // TODO: could be removed if we pre-open files (see `try_allocate_cow_pages`)
            (
                libc::SYS_open,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(OFlags::RDONLY.bits()),
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            (libc::SYS_close, vec![]),
        ];
        let rule_map: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
            rules.into_iter().collect();
        let filter = SeccompFilter::new(
            rule_map,
            // In debug builds, log violations instead of silently returning an error so that
            // it won't fail silently during development (which may be hard to debug).
            if cfg!(debug_assertions) {
                SeccompAction::Trap
            } else {
                SeccompAction::Errno(libc::EINVAL.cast_unsigned())
            },
            SeccompAction::Allow,
            seccompiler::TargetArch::x86_64,
        )
        .unwrap();
        // TODO: bpf program can be compiled offline
        let bpf_prog: BpfProgram = filter.try_into().unwrap();

        // seccomp TSYNC to confine all pre-existing threads (e.g., the network worker).
        seccompiler::apply_filter_all_threads(&bpf_prog).unwrap();
    }
}

impl litebox::platform::Provider for LinuxUserland {}

impl litebox::platform::SignalProvider for LinuxUserland {
    type Signal = litebox_common_linux::signal::Signal;

    fn take_pending_signals(&self, mut f: impl FnMut(Self::Signal)) {
        let sigs = take_pending_host_signals();
        for sig in sigs {
            f(sig);
        }
    }
}

/// Atomically takes the per-thread pending host signal bitmask.
fn take_pending_host_signals() -> litebox_common_linux::signal::SigSet {
    // Atomically swap the per-thread pending signals with zero.
    // Only the low 32 bits are used (covers traditional signals 1-31).
    let lo: u32;
    unsafe {
        core::arch::asm!(
            "xor {tmp:e}, {tmp:e}",
            concat!("xchg DWORD PTR ", tls!("pending_host_signals"), ", {tmp:e}"),
            tmp = out(reg) lo,
            options(nostack)
        );
    }
    litebox_common_linux::signal::SigSet::from_u64(u64::from(lo))
}

/// Runs a guest thread using the provided shim and the given initial context.
///
/// This will run until the thread terminates or returns.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread<T>(shim: T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(&shim, ctx, GuestXstateInit::Initial);
}

/// Run a guest thread using a reference to the shim.
///
/// Unlike `run_thread`, this version takes a reference instead of ownership,
/// avoiding struct moves that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn run_thread_ref<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, GuestXstateInit::Initial);
}

/// Re-enter a guest thread using a reference to the shim.
///
/// This version takes a reference instead of ownership, avoiding struct moves
/// that could invalidate internal state.
///
/// # Safety
/// The context must be valid guest context.
pub unsafe fn reenter_thread<T>(shim: &T, ctx: &mut litebox_common_linux::PtRegs)
where
    T: litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
{
    run_thread_inner(shim, ctx, GuestXstateInit::Reenter);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    xstate_init: GuestXstateInit,
) {
    let reenter = matches!(xstate_init, GuestXstateInit::Reenter);
    activate_xstate(xstate_init);
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
        });
    });
}

/// Non-guest threads (e.g., network workers, background tasks) should call this
/// function at the start of their execution so the kernel only delivers
/// `SIGALRM` / `SIGINT` to guest threads, which have the proper signal-handler
/// context to re-enter the shim.
fn block_guest_signals() {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
    }
}

/// Spawn a non-guest ("host") thread that automatically blocks guest interrupt
/// signals before running `f`.
///
/// Every background thread created by a runner (network workers, I/O helpers,
/// etc.) should use this function instead of [`std::thread::spawn`] to ensure
/// that `SIGALRM` and `SIGINT` are only delivered to guest threads.
///
/// # Example
///
/// ```ignore
/// let handle = litebox_platform_linux_userland::spawn_host_thread(move || {
///     // This thread will never receive SIGALRM or SIGINT.
///     do_background_work();
/// });
/// ```
pub fn spawn_host_thread<F, T>(f: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || {
        block_guest_signals();
        f()
    })
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
    xstate_init: GuestXstateInit,
) {
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, xstate_init);
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pthread_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(unsafe {
            libc::pthread_self()
        }))));
        CURRENT_THREAD.with_borrow_mut(|current| {
            assert!(
                current.is_none(),
                "nested with_thread_handle calls are not supported"
            );
            *current = Some(handle);
        });
        let _guard = litebox::utils::defer(|| {
            let current = CURRENT_THREAD.take().unwrap();
            *current.0.lock().unwrap() = None;
        });
        f()
    }

    /// Returns the current thread handle.
    fn current() -> Self {
        CURRENT_THREAD.with_borrow(|thread| {
            thread
                .clone()
                .expect("current_thread called outside of a LiteBox thread")
        })
    }

    /// Interrupts the thread, delivering a signal to it.
    fn interrupt(&self) {
        let thread = self.0.lock().unwrap();
        if let Some(&thread) = thread.as_ref() {
            unsafe {
                libc::pthread_kill(thread, INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed));
            }
        }
    }
}

impl litebox::platform::ThreadProvider for LinuxUserland {
    type ExecutionContext = litebox_common_linux::PtRegs;
    type ThreadSpawnError = std::io::Error;
    type ThreadHandle = ThreadHandle;

    unsafe fn spawn_thread(
        &self,
        ctx: &litebox_common_linux::PtRegs,
        init_thread: Box<
            dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
        >,
    ) -> Result<(), Self::ThreadSpawnError> {
        let ctx = ctx.clone();
        // Inherits the calling guest's saved extended CPU state.
        let xstate_init = GUEST_XSTATE.with_borrow(|guest| {
            guest.as_ref().map_or(GuestXstateInit::Initial, |guest| {
                GuestXstateInit::Inherited(guest.clone())
            })
        });
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new()
            .spawn(move || thread_start(init_thread, ctx, xstate_init))?;

        Ok(())
    }

    fn current_thread(&self) -> Self::ThreadHandle {
        ThreadHandle::current()
    }

    fn interrupt_thread(&self, thread: &Self::ThreadHandle) {
        thread.interrupt();
    }

    #[cfg(debug_assertions)]
    fn run_test_thread<R>(f: impl FnOnce() -> R) -> R {
        // Sets `gsbase = fsbase` (x86_64) or `fs = gs` (x86) on the current thread
        // to mirror the TLS base used in guest context, so that test threads can use the
        // same TLS access code as guest threads.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "rdfsbase {tmp}",
                "wrgsbase {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }

        ThreadHandle::run_with_handle(f)
    }
}

impl litebox::platform::TimerProvider for LinuxUserland {
    type TimerHandle = TimerHandle;
    type Signal = litebox_common_linux::signal::Signal;

    fn create_timer(
        &self,
        signal: Self::Signal,
    ) -> Result<Self::TimerHandle, litebox::platform::TimerCreationError> {
        // Create a POSIX per-process timer.  We always deliver via SIGALRM at
        // the kernel level (whose handler is already registered) and encode the
        // *desired* guest signal in `sigev_value.sival_int`.  The signal handler
        // reads `si_value` when `si_code == SI_TIMER` to determine which guest
        // signal to record.
        let mut sev: libc::sigevent = unsafe { core::mem::zeroed() };
        sev.sigev_notify = libc::SIGEV_SIGNAL;
        sev.sigev_signo = libc::SIGALRM;
        sev.sigev_value.sival_ptr = signal.as_i32() as *mut libc::c_void;

        let mut timer_id: libc::timer_t = std::ptr::null_mut();
        let ret =
            unsafe { libc::timer_create(libc::CLOCK_MONOTONIC, &raw mut sev, &raw mut timer_id) };
        assert!(
            ret == 0,
            "timer_create failed: {}",
            std::io::Error::last_os_error()
        );

        Ok(TimerHandle(timer_id))
    }
}

/// A timer handle backed by POSIX `timer_create` / `timer_settime`.
///
/// Each handle owns an independent kernel timer, so multiple timers can
/// coexist without interfering with each other.
pub struct TimerHandle(libc::timer_t);

// Safety: `timer_t` is an opaque kernel handle safe to send across threads.
unsafe impl Send for TimerHandle {}
unsafe impl Sync for TimerHandle {}

impl Drop for TimerHandle {
    fn drop(&mut self) {
        // Safety: we own the timer and it will not be used after drop.
        unsafe {
            libc::timer_delete(self.0);
        }
    }
}

impl litebox::platform::TimerHandle for TimerHandle {
    fn set_timer(&self, duration: core::time::Duration) {
        let its = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: duration.as_secs().cast_signed().trunc(),
                tv_nsec: duration.subsec_nanos().cast_signed().into(),
            },
        };
        // Safety: valid timer id and itimerspec.
        let ret = unsafe { libc::timer_settime(self.0, 0, &raw const its, std::ptr::null_mut()) };
        assert!(
            ret == 0,
            "timer_settime failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

impl litebox::platform::RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;

    fn update_waker(&self, waker: Option<litebox::event::wait::Waker<Self>>)
    where
        Self: litebox::sync::RawSyncPrimitivesProvider,
    {
        let mut waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
        unsafe {
            core::arch::asm!(
                concat!("xchg ", tls!("wait_waker_addr"), ", {}"),
                inout(reg) waker_ptr,
                options(nostack),
            );
        }
        if !waker_ptr.is_null() {
            // SAFETY: old waker_ptr was created by Box::into_raw in a previous call to update_waker.
            unsafe { drop(Box::from_raw(waker_ptr)) };
        }
    }
}

pub struct RawMutex {
    // The `inner` is the value shown to the outside world as an underlying atomic.
    inner: AtomicU32,
}

impl RawMutex {
    const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
        }
    }

    fn block_or_maybe_timeout(
        &self,
        val: u32,
        timeout: Option<Duration>,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        // We wait on the futex, with a timeout if needed
        match futex_timeout(
            &self.inner,
            FutexOperation::Wait,
            /* expected value */ val,
            timeout,
            /* ignored */ None,
        ) {
            Ok(0) | Err(syscalls::Errno::EINTR) => Ok(UnblockedOrTimedOut::Unblocked),
            Err(syscalls::Errno::EAGAIN) => Err(ImmediatelyWokenUp),
            Err(syscalls::Errno::ETIMEDOUT) => Ok(UnblockedOrTimedOut::TimedOut),
            Err(e) => {
                panic!("Unexpected errno={e} for FUTEX_WAIT")
            }
            _ => unreachable!(),
        }
    }
}

impl litebox::platform::RawMutex for RawMutex {
    const INIT: Self = Self::new();

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.inner
    }

    fn wake_many(&self, n: usize) -> usize {
        assert!(n > 0);
        let n: u32 = n.try_into().unwrap();

        futex_val2(
            &self.inner,
            FutexOperation::Wake,
            /* number to wake up */ n,
            /* val2: ignored */ 0,
            /* uaddr2: ignored */ None,
        )
        .expect("failed to wake up waiters")
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
            syscalls::syscall3(
                syscalls::Sysno::write,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_ptr() as usize,
                packet.len(),
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
            syscalls::syscall3(
                syscalls::Sysno::read,
                usize::try_from(tun_socket_fd.as_raw_fd()).unwrap(),
                packet.as_mut_ptr() as usize,
                packet.len(),
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
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        SystemTime {
            #[cfg_attr(target_arch = "x86_64", expect(clippy::useless_conversion))]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl litebox::platform::Instant for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl litebox::platform::SystemTime for SystemTime {
    const UNIX_EPOCH: Self = SystemTime {
        inner: Duration::ZERO,
    };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        self.inner
            .checked_sub(earlier.inner)
            .ok_or_else(|| earlier.inner.checked_sub(self.inner).unwrap())
    }
}

type UserMutPtr<T> = litebox::platform::common_providers::userspace_pointers::UserMutPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
type UserConstPtr<T> = litebox::platform::common_providers::userspace_pointers::UserConstPtr<
    litebox::platform::common_providers::userspace_pointers::NoValidation,
    T,
>;
impl litebox::platform::RawPointerProvider for LinuxUserland {
    type RawConstPointer<T: FromBytes> = UserConstPtr<T>;
    type RawMutPointer<T: FromBytes + IntoBytes> = UserMutPtr<T>;
}

/// Operations currently supported by the safer variants of the Linux futex syscall
/// ([`futex_timeout`] and [`futex_val2`]).
#[repr(i32)]
enum FutexOperation {
    Wait = litebox_common_linux::FUTEX_WAIT,
    Wake = litebox_common_linux::FUTEX_WAKE,
}

/// Safer invocation of the Linux futex syscall, with the "timeout" variant of the arguments.
#[expect(clippy::similar_names, reason = "sec/nsec are as needed by libc")]
fn futex_timeout(
    uaddr: &AtomicU32,
    futex_op: FutexOperation,
    val: u32,
    timeout: Option<Duration>,
    uaddr2: Option<&AtomicU32>,
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
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
        litebox_common_linux::Timespec { tv_sec, tv_nsec }
    });
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            if let Some(t) = timeout.as_ref() {
                core::ptr::from_ref(t) as usize
            } else {
                0 // No timeout
            },
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            0,
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
) -> Result<usize, syscalls::Errno> {
    let uaddr: *const AtomicU32 = std::ptr::from_ref(uaddr);
    let futex_op: i32 = futex_op as _;
    let uaddr2: *const AtomicU32 = uaddr2.map_or(std::ptr::null(), |u| u);
    unsafe {
        syscalls::syscall6(
            {
                #[cfg(target_arch = "x86_64")]
                {
                    syscalls::Sysno::futex
                }
            },
            uaddr as usize,
            usize::try_from(futex_op).unwrap(),
            val as usize,
            val2 as usize,
            uaddr2 as usize,
            // argument `val3` is ignored for this futex operation;
            0,
        )
    }
}

impl litebox::platform::StdioProvider for LinuxUserland {
    fn read_from_stdin(&self, buf: &mut [u8]) -> Result<usize, litebox::platform::StdioReadError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::read,
                usize::try_from(litebox_common_linux::STDIN_FILENO).unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioReadError::Closed,
            _ => panic!("unhandled error {err}"),
        })
    }

    fn write_to(
        &self,
        stream: litebox::platform::StdioOutStream,
        buf: &[u8],
    ) -> Result<usize, litebox::platform::StdioWriteError> {
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                usize::try_from(match stream {
                    litebox::platform::StdioOutStream::Stdout => {
                        litebox_common_linux::STDOUT_FILENO
                    }
                    litebox::platform::StdioOutStream::Stderr => {
                        litebox_common_linux::STDERR_FILENO
                    }
                })
                .unwrap(),
                buf.as_ptr() as usize,
                buf.len(),
            )
        }
        .map_err(|err| match err {
            syscalls::Errno::EPIPE => litebox::platform::StdioWriteError::Closed,
            _ => panic!("unhandled error {err}"),
        })
    }

    fn is_a_tty(&self, stream: litebox::platform::StdioStream) -> bool {
        self.stdio_is_tty[stream as usize]
    }
}

unsafe extern "C" {
    // Defined in asm blocks above
    fn syscall_callback() -> isize;
    fn exception_callback();
    fn interrupt_callback();
    fn interrupt_callback_no_xsave();
    fn switch_to_guest_start();
    fn switch_to_guest_end();
}

unsafe extern "C-unwind" fn init_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.init(ctx));
}

unsafe extern "C-unwind" fn reenter_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.reenter(ctx));
}

/// Handles Linux syscalls and dispatches them to LiteBox implementations.
///
/// Returns only if the guest thread is exiting. Otherwise, resumes the guest
/// without returning.
///
/// # Safety
///
/// - The `ctx` pointer must be valid pointer to a `litebox_common_linux::PtRegs` structure.
/// - If any syscall argument is a pointer, it must be valid.
///
/// # Panics
///
/// Unsupported syscalls or arguments would trigger a panic for development
/// purposes.
#[allow(clippy::cast_sign_loss)]
unsafe extern "C-unwind" fn syscall_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.syscall(ctx));
}

extern "C-unwind" fn exception_handler(
    thread_ctx: &mut ThreadContext,
    trapno: usize,
    error: usize,
    cr2: usize,
) {
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
        kernel_mode: false,
    };
    thread_ctx.call_shim(|shim, ctx| shim.exception(ctx, &info));
}

extern "C-unwind" fn interrupt_handler(thread_ctx: &mut ThreadContext) {
    thread_ctx.call_shim(|shim, ctx| shim.interrupt(ctx));
}

/// Calls `f` in order to call into a shim entrypoint.
impl ThreadContext<'_> {
    fn call_shim(
        &mut self,
        f: impl FnOnce(
            &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
            &mut litebox_common_linux::PtRegs,
        ) -> ContinueOperation,
    ) {
        // Clear the interrupt flag before calling the shim, since we've handled it
        // now (by calling into the shim), and it might be set again by the shim
        // before returning.
        unsafe {
            core::arch::asm!(
                concat!("mov BYTE PTR ", tls!("interrupt"), ", 0"),
                options(nostack, preserves_flags)
            );
        }
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        syscall_callback as *const () as usize
    }

    fn get_vdso_address(&self) -> Option<usize> {
        // Enabling VDSO on x86 causes glibc to not set a restorer in signal
        // handlers, which we do not currently support. Disable VDSO for
        // now.
        //
        // TODO: implement VDSO in the shim, don't try to pass through the
        // platform VDSO.
        None
    }
}

thread_local! {
    // Use `ManuallyDrop` for more efficient TLS accesses, since this is always
    // dropped manually before the thread exits.
    static PLATFORM_TLS: Cell<*mut ()> = const { Cell::new(core::ptr::null_mut()) };
}

/// LinuxUserland platform's thread-local storage implementation.
unsafe impl litebox::platform::ThreadLocalStorageProvider for LinuxUserland {
    fn get_thread_local_storage() -> *mut () {
        PLATFORM_TLS.get()
    }

    unsafe fn replace_thread_local_storage(value: *mut ()) -> *mut () {
        PLATFORM_TLS.replace(value)
    }
}

static mut NEXT_SA: [libc::sigaction; 64] = unsafe { core::mem::zeroed() };
static INTERRUPT_SIGNAL_NUMBER: AtomicI32 = AtomicI32::new(0);

fn register_exception_handlers() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        fn sigaction(sig: i32, sa: Option<&libc::sigaction>, old_sa: &mut libc::sigaction) {
            unsafe {
                let r = libc::sigaction(
                    sig,
                    sa.map_or(std::ptr::null(), |sa| &raw const *sa),
                    &raw mut *old_sa,
                );
                assert!(
                    r >= 0,
                    "failed to query existing signal handler for signal {}: {}",
                    sig,
                    std::io::Error::last_os_error()
                );
            }
        }

        let interrupt_signal = {
            // Find an RT signal number for interrupt handling.
            let sig = (libc::SIGRTMIN()..=libc::SIGRTMAX())
                .find(|&i| {
                    let mut old_sa = unsafe { core::mem::zeroed() };
                    sigaction(i, None, &mut old_sa);
                    old_sa.sa_sigaction == libc::SIG_DFL
                })
                .expect("no available real-time signal for interrupt handling");

            let mut sa: libc::sigaction = unsafe { core::mem::zeroed() };
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
            sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
            let mut old_sa = unsafe { core::mem::zeroed() };
            sigaction(sig, Some(&sa), &mut old_sa);
            assert_eq!(
                old_sa.sa_sigaction,
                libc::SIG_DFL,
                "signal {sig} handler already installed",
            );
            INTERRUPT_SIGNAL_NUMBER.store(sig, Ordering::Relaxed);
            sig
        };

        let exception_signals = &[
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGTRAP,
            // We'd like to log forbidden syscalls in debug mode
            #[cfg(debug_assertions)]
            libc::SIGSYS,
        ];
        for &sig in exception_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = exception_signal_handler as *const () as usize;
                // Block the interrupt signal while handling exceptions to avoid
                // saving the exception signal handler state as guest state.
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                // Note: the handler could start running before this call even
                // returns, so pass `&mut NEXT_SA` directly.
                sigaction(
                    sig,
                    Some(&sa),
                    &mut NEXT_SA[sig.reinterpret_as_unsigned() as usize],
                );
            }
        }

        // Note that non-guest threads should block these signals, so it always fires on a guest thread.
        let traditional_signals = &[libc::SIGINT, libc::SIGALRM];
        for &sig in traditional_signals {
            unsafe {
                let mut sa: libc::sigaction = core::mem::zeroed();
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                sa.sa_sigaction = interrupt_signal_handler as *const () as usize;
                // Block the interrupt signal while handling signals
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                let mut old_sa = core::mem::zeroed();
                sigaction(sig, Some(&sa), &mut old_sa);
                assert_eq!(
                    old_sa.sa_sigaction,
                    libc::SIG_DFL,
                    "signal {sig} handler already installed",
                );
            }
        }
    });
}

/// Runs `f` with an alternate signal stack set up.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let alt_stack_size = libc::SIGSTKSZ * 2;
    let guard_page_size = 0x1000;
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            guard_page_size + alt_stack_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert!(
        stack_base != libc::MAP_FAILED,
        "failed to allocate memory for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );
    let _unmap_guard = litebox::utils::defer(|| {
        let r = unsafe { libc::munmap(stack_base, guard_page_size + alt_stack_size) };
        assert!(
            r == 0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    });

    // Set up a guard page to catch stack overflows.
    let r = unsafe { libc::mprotect(stack_base, guard_page_size, libc::PROT_NONE) };
    assert!(
        r == 0,
        "failed to set guard page for alternate signal stack: {}",
        std::io::Error::last_os_error()
    );

    let alt_stack = libc::stack_t {
        ss_sp: stack_base.cast(),
        ss_flags: 0,
        ss_size: alt_stack_size,
    };
    let mut oss = libc::stack_t {
        ss_sp: std::ptr::null_mut(),
        ss_flags: 0,
        ss_size: 0,
    };
    unsafe {
        let r = libc::sigaltstack(&raw const alt_stack, &raw mut oss);
        assert!(
            r >= 0,
            "failed to set up alternate signal stack: {}",
            std::io::Error::last_os_error(),
        );
    }
    let _restore_guard = litebox::utils::defer(|| unsafe {
        let r = libc::sigaltstack(&raw const oss, std::ptr::null_mut());
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // Return an error code for the syscall and log it in debug mode.
    #[cfg(debug_assertions)]
    if signum == libc::SIGSYS {
        use core::fmt::Write as _;
        #[cfg(target_arch = "x86_64")]
        let eax_idx = libc::REG_RAX as usize;
        let sysno = context.uc_mcontext.gregs[eax_idx];
        context.uc_mcontext.gregs[eax_idx] = i64::from(-libc::EINVAL);
        // Signal-safe: format on the stack via arrayvec (no heap allocation).
        let mut buf = arrayvec::ArrayString::<320>::new();
        if sysno == libc::SYS_openat {
            #[cfg(target_arch = "x86_64")]
            let rsi = context.uc_mcontext.gregs[libc::REG_RSI as usize] as *const i8;
            let c_path = unsafe { core::ffi::CStr::from_ptr(rsi) };
            // libc may call `openat` for certain files that we can ignore, e.g., /proc/sys/vm/overcommit_memory.
            // Log the paths in case we need to allow some of them in the future.
            let _ = writeln!(buf, "INFO: openat with {c_path:?} is not allowed");
        } else {
            let _ = writeln!(buf, "WARNING: disallowed syscall invoked: {sysno}");
        }
        let _ = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::write,
                libc::STDERR_FILENO as usize,
                buf.as_ptr() as usize,
                buf.len(),
            )
        };
        return;
    }

    let Some(regs) = signal_handler_exit_guest(context, false) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    copy_signal_context(unsafe { &mut *regs }, context);

    // Ensure that `run_thread_arch` is linked in so that `exception_callback` is visible.
    let _ = run_thread_arch as *const () as usize;

    // Jump to exception_callback.
    let sigctx = &context.uc_mcontext;
    #[cfg(target_arch = "x86_64")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize].trunc(),
        sigctx.gregs[libc::REG_ERR as usize].trunc(),
        sigctx.gregs[libc::REG_CR2 as usize].trunc(),
    );
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // An asynchronous `SIGSEGV` (`info.si_code <= 0`) can interrupt a fixup range.
    // Do not interpret it as a memory fault.
    if signum == libc::SIGSEGV && info.si_code > 0 {
        let ip: usize = {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize]
                    .reinterpret_as_unsigned()
                    .trunc()
            }
        };
        if let Some(fixup_addr) = litebox::mm::exception_table::search_exception_tables(ip) {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    fixup_addr.reinterpret_as_signed() as i64;
            }
            return;
        }
    }

    unsafe {
        let next_sa = &NEXT_SA[signum.reinterpret_as_unsigned() as usize];
        match next_sa.sa_sigaction {
            libc::SIG_DFL => {
                // Block this signal and raise.
                let mut set: libc::sigset_t = core::mem::zeroed();
                libc::sigemptyset(&raw mut set);
                libc::sigaddset(&raw mut set, signum);
                libc::sigprocmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
                libc::raise(signum);
                unreachable!()
            }
            libc::SIG_IGN => {}
            _ => {
                // Call the next handler
                if next_sa.sa_flags & libc::SA_SIGINFO == 0 {
                    let handler: extern "C" fn(libc::c_int) =
                        core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum);
                } else {
                    let handler: extern "C" fn(
                        libc::c_int,
                        *mut libc::siginfo_t,
                        *mut libc::ucontext_t,
                    ) = core::mem::transmute(next_sa.sa_sigaction);
                    handler(signum, info, context);
                }
            }
        }
    }
}

/// Records a pending host signal in the `.tbss` bitmask and wakes any condvar
/// the thread is blocked on.
///
/// # Safety
///
/// Must be called from a signal handler on a guest thread whose saved host TLS
/// segment register is valid.
unsafe fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let mask: u32 = 1u32 << (signal.as_i32() - 1);
    unsafe {
        core::arch::asm!(
            concat!("lock or DWORD PTR ", saved_tls!("pending_host_signals"), ", {mask:e}"),
            mask = in(reg) mask,
            options(nostack)
        );
    }
    let waker_addr: usize;
    unsafe {
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("wait_waker_addr")),
            out(reg) waker_addr,
            options(nostack, preserves_flags)
        );
    }
    if waker_addr == 0 {
        return;
    }
    // SAFETY: if `waker_addr` is not zero, that means the current thread is suspended
    // to handle this signal and it points to a valid Waker whose lifetime spans the
    // entire interruptible wait, set by [`RawMutexProvider::update_waker`].
    let waker = unsafe { &*(waker_addr as *const litebox::event::wait::Waker<LinuxUserland>) };
    waker.wake();
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    #[cfg(debug_assertions)]
    let raise_signal = |signum: libc::c_int, info: &libc::siginfo_t| {
        // Block the signal on this non-guest thread so the kernel won't
        // deliver it here again, then re-raise as process-directed so a
        // guest thread picks it up.
        //
        // This should only be called by test threads (spawned via cargo test).
        // Other non-guest threads like network worker threads should have already blocked these signals.
        unsafe {
            let mut set: libc::sigset_t = core::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, signum);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
            let val = info.si_value();
            libc::sigqueue(libc::getpid(), signum, val);
        }
    };

    // Record host-originated signals (SIGINT, SIGALRM, etc.) in the
    // per-thread pending bitmask so the shim can forward them to the guest.
    // TODO: no realtime signal support for now.
    if signum > 0 && signum < 32 {
        // For timer-originated signals (and their re-raises via `sigqueue`),
        // the desired guest signal is encoded in `si_value.sival_ptr`
        // (set by `create_timer`).  For other sources (e.g. `kill()`), use
        // the signal number directly.
        let guest_signum = if info.si_code == libc::SI_TIMER || info.si_code == libc::SI_QUEUE {
            unsafe { info.si_value().sival_ptr as libc::c_int }
        } else {
            signum
        };

        // Only record signals that can be forwarded to the guest as
        // litebox_common_linux::signal::Signal. Unknown signals are silently dropped.
        let Ok(signal) = litebox_common_linux::signal::Signal::try_from(guest_signum) else {
            return;
        };

        // Check whether the saved host TLS segment is valid (i.e. this is a
        // guest thread). If not, re-raise the signal process-wide.
        let is_guest_thread;
        #[cfg(target_arch = "x86_64")]
        {
            let gsbase: u64;
            unsafe { core::arch::asm!("rdgsbase {}", out(reg) gsbase) };
            is_guest_thread = gsbase != 0;
        }

        if is_guest_thread {
            // SAFETY: we verified the saved host TLS segment is valid above.
            unsafe { record_pending_signal(signal) };
        } else {
            #[cfg(debug_assertions)]
            raise_signal(signum, info);
            return;
        }
    }

    // The interrupt signal can arrive in different contexts:
    // 1. The thread is running in the host at the beginning of the syscall
    //    handler. Do nothing--the syscall handler will handle the interrupt.
    // 2. The thread is running in the host, with in_guest = 0. Just record that
    //    an interrupt is pending; it will be checked next time we switch to the
    //    guest.
    // 3. The thread is running in the host, with in_guest = 1, in the middle of
    //    restoring the guest context. We need to jump to the interrupt handler
    //    without overwriting the saved guest context.
    // 4. The thread is running in the guest. We need to save the context and
    //    jump to the interrupt handler.
    //
    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .trunc();

    // Case 1: at the beginning of the syscall handler.
    //
    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if ip == syscall_callback as *const () as usize {
        // No need to clear `in_guest` or set interrupt; the syscall handler will
        // clear `in_guest` and call into the shim.
        return;
    }

    // Clear `in_guest` and set `interrupt`.
    let Some(regs) = signal_handler_exit_guest(context, true) else {
        // Case 2: not in guest.
        return;
    };

    // If the interrupt happened while returning to the guest, don't overwrite
    // the saved context.
    let in_switch_to_guest = (switch_to_guest_start as *const () as usize
        ..switch_to_guest_end as *const () as usize)
        .contains(&ip);
    if in_switch_to_guest {
        // Case 3: in the middle of restoring guest context. Don't overwrite it.
    } else {
        // Case 4: in guest. Copy out the context.
        copy_signal_context(unsafe { &mut *regs }, context);
    }
    // Cases 3 and 4: jump to interrupt handler.
    set_signal_return(
        context,
        if in_switch_to_guest {
            interrupt_callback_no_xsave
        } else {
            interrupt_callback
        },
        0,
        0,
        0,
        0,
    );
}

impl litebox::platform::CrngProvider for LinuxUserland {
    fn fill_bytes_crng(&self, buf: &mut [u8]) {
        getrandom::fill(buf).expect("getrandom failed");
    }
}

impl litebox::platform::DerivedKeyProvider for LinuxUserland {
    fn derive_key<E>(
        &self,
        shim_kdf: Option<fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>>,
        params: litebox::platform::KDFParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        let Some(boot_id) = self.boot_id.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        };
        match shim_kdf {
            None => {
                // TODO: Ideally, we'd use something like argon2 or such here to support more shims,
                // but for now, we just return an error.
                Err(litebox::platform::DerivedKeyError::ShimKDFRequired)
            }
            Some(shim_kdf) => {
                // We trust the shim in this platform, since it is in the same trust boundary as us.
                // Thus (unlike some other platforms) we do not need to manually hide the "key", and
                // can just run the KDF as-is.
                //
                // Our key is actually just the boot ID itself.
                Ok(shim_kdf(boot_id, params)?)
            }
        }
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for LinuxUserland {
    type MapInfo = litebox_common_linux::vmap::NoopPhysPageMapInfo;

    fn validate_unowned(
        &self,
        _pages: &litebox_common_linux::vmap::PhysPageAddrArray<ALIGN>,
    ) -> Result<(), litebox_common_linux::vmap::PhysPointerError> {
        Err(litebox_common_linux::vmap::PhysPointerError::UnsupportedOperation)
    }

    unsafe fn protect(
        &self,
        _pages: &litebox_common_linux::vmap::PhysPageAddrArray<ALIGN>,
        _perms: litebox_common_linux::vmap::PhysPageMapPermissions,
    ) -> Result<(), litebox_common_linux::vmap::PhysPointerError> {
        Err(litebox_common_linux::vmap::PhysPointerError::UnsupportedOperation)
    }
}

/// Dummy `VmemPageFaultHandler`.
///
/// Page faults are handled transparently by the host Linux kernel.
/// Provided to satisfy trait bounds for `MemoryManager::handle_page_fault`.
impl litebox_common_linux::vmem::VmemPageFaultHandler for LinuxUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox_common_linux::vmem::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox_common_linux::vmem::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox_common_linux::vmem::VmFlags) -> bool {
        unreachable!("host kernel handles page faults for Linux userland")
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::thread::sleep;

    use litebox::{fs::OFlags, platform::RawMutex};

    use crate::LinuxUserland;

    extern crate std;

    #[test]
    fn test_raw_mutex() {
        let mutex = std::sync::Arc::new(super::RawMutex {
            inner: AtomicU32::new(0),
        });

        let copied_mutex = mutex.clone();
        std::thread::spawn(move || {
            sleep(core::time::Duration::from_millis(500));
            copied_mutex
                .inner
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            copied_mutex.wake_many(10);
        });

        assert!(mutex.block(0).is_ok());
    }

    #[test]
    fn asynchronous_sigsegv_does_not_trigger_exception_fixup() {
        const CHILD_ENV: &str = "LITEBOX_ASYNC_SIGSEGV_TEST_CHILD";

        if std::env::var_os(CHILD_ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::asynchronous_sigsegv_does_not_trigger_exception_fixup",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .status()
                .unwrap();
            assert!(status.success(), "subprocess failed: {status}");
            return;
        }

        unsafe {
            let mut action: libc::sigaction = core::mem::zeroed();
            action.sa_sigaction = libc::SIG_IGN;
            assert_eq!(
                libc::sigaction(libc::SIGSEGV, &raw const action, core::ptr::null_mut(),),
                0
            );
        }
        let _platform = LinuxUserland::new(None);

        let target = unsafe { libc::pthread_self() };
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let sender_stop = stop.clone();
        let sender = std::thread::spawn(move || {
            while !sender_stop.load(Ordering::Relaxed) {
                assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGSEGV) }, 0);
                std::thread::yield_now();
            }
        });

        let src = vec![0x5a; 16 * 1024 * 1024];
        let mut dst = vec![0; src.len()];
        for _ in 0..16 {
            assert!(unsafe {
                litebox::mm::exception_table::memcpy_fallible(
                    dst.as_mut_ptr(),
                    src.as_ptr(),
                    src.len(),
                )
                .is_ok()
            });
        }
        stop.store(true, Ordering::Relaxed);
        sender.join().unwrap();
        assert_eq!(dst, src);
    }

    #[test]
    fn test_seccomp_filter() {
        let _platform: &LinuxUserland = LinuxUserland::new(None);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        let worker = super::spawn_host_thread(move || {
            worker_barrier.wait();
            worker_barrier.wait();
            assert_seccomp_filter();
        });

        // Finish worker setup before filtering; release it only after installation.
        barrier.wait();
        LinuxUserland::enable_seccomp_filter();
        barrier.wait();

        assert_seccomp_filter();
        worker.join().unwrap();
    }

    fn assert_seccomp_filter() {
        let pathname = c"/tmp/test_seccomp";
        let mkdir_res = unsafe {
            syscalls::syscall2(syscalls::Sysno::mkdir, pathname.as_ptr() as usize, 0o755)
        };
        assert_eq!(
            mkdir_res.unwrap_err(),
            syscalls::Errno::EINVAL,
            "mkdir should be blocked by seccomp filter"
        );

        let pathname =
            std::ffi::CString::new(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let open_res = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::open,
                pathname.as_ptr() as usize,
                OFlags::RDWR.bits() as usize,
            )
        };
        assert_eq!(
            open_res.unwrap_err(),
            syscalls::Errno::EINVAL,
            "open with RDWR should be blocked by seccomp filter"
        );
    }
}
