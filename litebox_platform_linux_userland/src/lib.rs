// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.
//!
//! The guest shares the host process's address space, so this platform does not isolate host
//! memory from the guest: guest code or fixed-address mappings can read or overwrite it.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use litebox::mm::vmap::VmapManager;
use litebox::platform::page_mgmt::{FixedAddressBehavior, MemoryRegionPermissions};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};
use litebox_platform::time::{
    Instant as InstantTrait, SystemTime as SystemTimeTrait, TimeProvider,
};
use std::cell::Cell;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;

use zerocopy::{FromBytes, IntoBytes};

extern crate alloc;

#[cfg_attr(target_arch = "aarch64", path = "aarch64.rs")]
#[cfg_attr(target_arch = "x86_64", path = "x86_64.rs")]
mod arch;
mod page_mgmt;
pub mod process;
pub mod shared_objects;

#[cfg(target_arch = "aarch64")]
use arch::{
    Aarch64GateSignalResult, GateInterruption, assert_tls_block_placement,
    canonicalize_runtime_aarch64_gate_signal_context, fatal_aarch64_runtime_state,
    signal_handler_capture_guest_vector_state, signal_handler_set_interrupt,
    sync_instruction_stream,
};
#[cfg(target_arch = "x86_64")]
use arch::{copy_signal_context, interrupt_callback_no_xsave, signal_handler_exit_guest};
use arch::{
    exception_callback, exception_entry, interrupt_callback, interrupt_entry,
    is_guest_thread_from_signal_context, prepare_guest_vector_state, replace_guest_thread_marker,
    run_thread_arch, set_guest_thread_marker, set_signal_return, switch_to_guest,
};

#[cfg(all(test, target_arch = "aarch64"))]
const AT_FDCWD: usize = (litebox_common_linux::AT_FDCWD as isize).cast_unsigned();

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    /// If [`Self::initialize_boot_specific_kdf_support`] has been run, this is set to a value that
    /// is persistent across multiple process executions, however, it is ephemeral across true
    /// reboots.
    boot_id: std::sync::OnceLock<Vec<u8>>,
    /// Receives the host shared objects that the broker delivers, once the runner installs it.
    shared_objects: std::sync::OnceLock<shared_objects::SharedObjectChannel>,
}

/// Determines how an x86-64 guest accesses its thread-local storage.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestTlsMode {
    /// A Linux guest uses FS as its TLS base.
    Linux = 1,
    /// A Windows guest uses GS as its TEB base.
    Windows = 2,
}

#[cfg(target_arch = "x86_64")]
const GUEST_TLS_MODE_UNCONFIGURED: u8 = 0;

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
static GUEST_TLS_MODE: std::sync::atomic::AtomicU8 =
    std::sync::atomic::AtomicU8::new(GUEST_TLS_MODE_UNCONFIGURED);

impl core::fmt::Debug for LinuxUserland {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinuxUserland").finish_non_exhaustive()
    }
}

impl LinuxUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    pub fn new() -> &'static Self {
        #[cfg(target_arch = "aarch64")]
        assert_tls_block_placement();

        register_exception_handlers();

        let platform = Self {
            boot_id: std::sync::OnceLock::new(),
            shared_objects: std::sync::OnceLock::new(),
        };
        Box::leak(Box::new(platform))
    }

    /// Creates a fresh platform around signal handlers inherited by a native process clone.
    ///
    /// # Safety
    ///
    /// The caller must be the sole thread in a process cloned from an initialized
    /// [`LinuxUserland`] runner. The child must not use or destroy the copied platform instance.
    pub unsafe fn new_after_process_clone() -> &'static Self {
        #[cfg(target_arch = "aarch64")]
        assert_tls_block_placement();
        // Independently usable bootstrap: prepare_fork_child need not have run.
        // SAFETY: sole surviving clone thread; copied guest guards cannot resume.
        unsafe {
            arch::reset_after_fork();
        }

        Box::leak(Box::new(Self {
            boot_id: std::sync::OnceLock::new(),
            shared_objects: std::sync::OnceLock::new(),
        }))
    }

    /// Installs the socket over which the broker delivers host objects that this process must
    /// hold itself, such as memfds. See [`shared_objects`].
    ///
    /// # Panics
    ///
    /// Panics if a socket was already installed.
    pub fn set_shared_object_channel(&self, socket: std::os::fd::OwnedFd) {
        assert!(
            self.shared_objects
                .set(shared_objects::SharedObjectChannel::new(socket))
                .is_ok(),
            "shared-object channel already installed"
        );
    }

    /// Takes the descriptor that the broker delivered under `token`, waiting for it if it has
    /// not arrived yet. See [`shared_objects::SharedObjectChannel::take`].
    pub fn take_shared_object(&self, token: u64) -> std::io::Result<std::os::fd::OwnedFd> {
        self.shared_objects
            .get()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "no shared-object channel is installed",
                )
            })?
            .take(token)
    }

    /// Configures the process-wide guest TLS mode.
    ///
    /// # Panics
    ///
    /// Panics if a different mode has already been configured.
    #[cfg(target_arch = "x86_64")]
    pub fn set_guest_tls_mode(&self, mode: GuestTlsMode) {
        let mode = mode as u8;
        if let Err(configured_mode) = GUEST_TLS_MODE.compare_exchange(
            GUEST_TLS_MODE_UNCONFIGURED,
            mode,
            Ordering::Release,
            Ordering::Acquire,
        ) {
            assert_eq!(
                configured_mode, mode,
                "guest TLS mode is already configured"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn guest_tls_mode() -> GuestTlsMode {
        match GUEST_TLS_MODE.load(Ordering::Relaxed) {
            mode if mode == GuestTlsMode::Linux as u8 => GuestTlsMode::Linux,
            mode if mode == GuestTlsMode::Windows as u8 => GuestTlsMode::Windows,
            GUEST_TLS_MODE_UNCONFIGURED => panic!("guest TLS mode is not configured"),
            _ => unreachable!("invalid guest TLS mode"),
        }
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

    #[allow(
        clippy::missing_panics_doc,
        reason = "the seccomp filter rules are hardcoded and not expected to fail"
    )]
    /// Installs the runner seccomp filter on the threads selected by `scope`.
    ///
    /// Broker transport exceptions are restricted to the supplied descriptors. If
    /// `native_fork_stream_fd` is given, the runner may natively clone itself, and the clone
    /// negotiates its broker association over a socket it places at that descriptor number. If
    /// `shared_object_fd` is given, the runner may receive the host shared objects the broker
    /// delivers over that socket (see [`Self::set_shared_object_channel`]).
    pub fn enable_seccomp_filter(
        positional_io_fds: &[std::os::fd::RawFd],
        shutdown_fds: &[std::os::fd::RawFd],
        scope: SeccompScope,
        native_fork_stream_fd: Option<std::os::fd::RawFd>,
        shared_object_fd: Option<std::os::fd::RawFd>,
    ) {
        use seccompiler::{
            BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition,
            SeccompFilter, SeccompRule,
        };

        let mut rules = vec![
            // Terminal and broker I/O
            (libc::SYS_read, vec![]),
            (libc::SYS_write, vec![]),
            // The AArch64 (asm-generic) syscall table has no `poll`; glibc
            // implements `poll(3)` there via `ppoll`.
            #[cfg(target_arch = "x86_64")]
            (libc::SYS_poll, vec![]),
            #[cfg(target_arch = "aarch64")]
            (libc::SYS_ppoll, vec![]),
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
            // CPU-time accounting
            (libc::SYS_getrusage, vec![]),
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
            // Connected UnixStream I/O may use sendto/recvfrom rather than raw
            // read/write. Limit these rules to connected-socket calls that do
            // not name a peer address.
            (
                libc::SYS_sendto,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(4, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                        SeccompCondition::new(5, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            (
                libc::SYS_recvfrom,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(4, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                        SeccompCondition::new(5, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)
                            .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
            (libc::SYS_close, vec![]),
        ];
        arch::add_seccomp_rules(&mut rules);
        let arg_eq = |index, value: u64| {
            SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value).unwrap()
        };
        let as_arg = |value: i32| {
            u64::from(u32::try_from(value).expect("syscall argument must be non-negative"))
        };
        if let Some(stream_fd) = native_fork_stream_fd {
            // The clone's descriptor-specific rules are confined to its control socket.
            let stream = as_arg(stream_fd);
            let socket_timeouts = [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO]
                .into_iter()
                .map(|option| {
                    SeccompRule::new(vec![
                        arg_eq(0, stream),
                        arg_eq(1, as_arg(libc::SOL_SOCKET)),
                        arg_eq(2, as_arg(option)),
                    ])
                    .unwrap()
                })
                .collect::<Vec<_>>();

            rules.extend([
                // Parent: the clone, and cleanup of a clone the broker did not adopt.
                (
                    libc::SYS_clone,
                    vec![
                        SeccompRule::new(vec![arg_eq(
                            0,
                            as_arg(libc::CLONE_PARENT | libc::CLONE_PIDFD | libc::SIGCHLD),
                        )])
                        .unwrap(),
                    ],
                ),
                (
                    libc::SYS_pidfd_send_signal,
                    vec![SeccompRule::new(vec![arg_eq(1, as_arg(libc::SIGKILL))]).unwrap()],
                ),
                // Child: descriptor cleanup, placing the control socket, and negotiation over it.
                (libc::SYS_close_range, vec![]),
                (
                    libc::SYS_recvmsg,
                    vec![SeccompRule::new(vec![arg_eq(0, stream)]).unwrap()],
                ),
                (libc::SYS_getsockopt, socket_timeouts.clone()),
                (libc::SYS_setsockopt, socket_timeouts),
                // Duplicates the process's own descriptors to the lowest free number at or above
                // `stream_fd`: the clone moves its socket there once the descriptors above the
                // standard streams are closed, and the transport duplicates the socket into its
                // shutdown handle.
                (
                    libc::SYS_fcntl,
                    vec![
                        SeccompRule::new(vec![
                            arg_eq(1, as_arg(libc::F_DUPFD_CLOEXEC)),
                            arg_eq(2, stream),
                        ])
                        .unwrap(),
                    ],
                ),
            ]);
        }
        if !positional_io_fds.is_empty() {
            // Broker shared memory uses positional descriptor I/O.
            let fd_rules = || {
                positional_io_fds
                    .iter()
                    .map(|fd| SeccompRule::new(vec![arg_eq(0, as_arg(*fd))]).unwrap())
                    .collect()
            };
            rules.push((libc::SYS_pread64, fd_rules()));
            rules.push((libc::SYS_pwrite64, fd_rules()));
        }
        if !shutdown_fds.is_empty() {
            // Association failure shuts down the control socket in both
            // directions to interrupt local and peer liveness waits.
            let shutdown_rules = shutdown_fds
                .iter()
                .map(|fd| {
                    SeccompRule::new(vec![
                        arg_eq(0, as_arg(*fd)),
                        arg_eq(1, as_arg(libc::SHUT_RDWR)),
                    ])
                    .unwrap()
                })
                .collect();
            rules.push((libc::SYS_shutdown, shutdown_rules));
        }
        if let Some(fd) = shared_object_fd {
            rules.push((
                libc::SYS_recvmsg,
                vec![SeccompRule::new(vec![arg_eq(0, as_arg(fd))]).unwrap()],
            ));
        }
        // A syscall may have rules from more than one source, such as `recvmsg` on both the
        // native fork socket and the shared-object socket; any of them allows it.
        let mut rule_map = std::collections::BTreeMap::<i64, Vec<SeccompRule>>::new();
        for (syscall, syscall_rules) in rules {
            match rule_map.entry(syscall) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(syscall_rules);
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    // An empty rule list allows the syscall unconditionally.
                    if !entry.get().is_empty() && !syscall_rules.is_empty() {
                        entry.get_mut().extend(syscall_rules);
                    } else {
                        entry.get_mut().clear();
                    }
                }
            }
        }
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
            if cfg!(target_arch = "x86_64") {
                seccompiler::TargetArch::x86_64
            } else {
                seccompiler::TargetArch::aarch64
            },
        )
        .unwrap();
        // TODO: bpf program can be compiled offline
        let bpf_prog: BpfProgram = filter.try_into().unwrap();

        match scope {
            SeccompScope::CallingThread => seccompiler::apply_filter(&bpf_prog),
            SeccompScope::AllThreads => seccompiler::apply_filter_all_threads(&bpf_prog),
        }
        .unwrap();
    }
}

/// Threads confined by [`LinuxUserland::enable_seccomp_filter`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeccompScope {
    /// The calling thread and threads it creates afterward.
    CallingThread,
    /// All threads of the process including pre-existing ones.
    AllThreads,
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
    let lo = arch::take_pending_host_signals_bits();
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
    run_thread_inner(&shim, ctx, GuestVectorStateMode::Fresh);
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
    run_thread_inner(shim, ctx, GuestVectorStateMode::Fresh);
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
    run_thread_inner(shim, ctx, GuestVectorStateMode::Resume);
}

enum GuestVectorStateMode {
    Fresh,
    Resume,
    Inherited(Box<litebox_common_linux::GuestVectorState>),
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    vector_state_mode: GuestVectorStateMode,
) {
    prepare_guest_vector_state(match &vector_state_mode {
        GuestVectorStateMode::Inherited(state) => Some(state.as_ref()),
        GuestVectorStateMode::Fresh | GuestVectorStateMode::Resume => None,
    });
    process::record_first_guest_entry_depth();
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    let _guest_thread = GuestThreadMarker::enter();
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(
                &mut thread_ctx,
                ctx_ptr,
                u8::from(matches!(vector_state_mode, GuestVectorStateMode::Resume)),
            );
        });
    });
}

/// Tracks the whole guest-thread lifetime and preserves nested-entry state.
struct GuestThreadMarker {
    previous: bool,
    _tp_registration: arch::Registration,
}

impl GuestThreadMarker {
    fn enter() -> Self {
        let registration = arch::Registration::enter();
        Self {
            previous: replace_guest_thread_marker(true),
            _tp_registration: registration,
        }
    }
}

impl Drop for GuestThreadMarker {
    fn drop(&mut self) {
        set_guest_thread_marker(self.previous);
    }
}

/// Non-guest threads (e.g., network workers, background tasks) should call this
/// function at the start of their execution so the kernel only delivers
/// `SIGALRM` / `SIGINT` to guest threads, which have the proper signal-handler
/// context to re-enter the shim.
fn guest_signal_set() -> libc::sigset_t {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&raw mut set);
        libc::sigaddset(&raw mut set, libc::SIGALRM);
        libc::sigaddset(&raw mut set, libc::SIGINT);
        let interrupt_signal = INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed);
        if interrupt_signal != 0 {
            libc::sigaddset(&raw mut set, interrupt_signal);
        }
        set
    }
}

struct GuestSignalMaskGuard {
    previous: libc::sigset_t,
}

impl Drop for GuestSignalMaskGuard {
    fn drop(&mut self) {
        // SAFETY: `previous` was populated by `pthread_sigmask` for this
        // thread and remains valid for the lifetime of the guard.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        debug_assert_eq!(result, 0, "failed to restore the thread signal mask");
    }
}

/// Runs `f` while blocking signals reserved for delivery to guest threads.
///
/// Threads spawned by `f` inherit the blocked mask. The calling thread's
/// previous mask is restored when `f` returns or unwinds.
///
/// # Panics
///
/// Panics if the calling thread's signal mask cannot be changed.
pub fn with_guest_signals_blocked<T>(f: impl FnOnce() -> T) -> T {
    let set = guest_signal_set();
    let mut previous = unsafe { std::mem::zeroed() };
    // SAFETY: `set` and `previous` are valid signal sets owned by this thread.
    let result =
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, &raw mut previous) };
    assert_eq!(result, 0, "failed to block guest signals");
    let _guard = GuestSignalMaskGuard { previous };
    f()
}

/// Unblocks signals reserved for delivery to guest threads on the calling thread.
///
/// # Panics
///
/// Panics if the calling thread's signal mask cannot be changed.
pub fn unblock_guest_signals() {
    let set = guest_signal_set();
    // SAFETY: `set` is a valid signal set and the null third argument means
    // the previous mask is not requested.
    let result =
        unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut()) };
    assert_eq!(result, 0, "failed to unblock guest signals");
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
    with_guest_signals_blocked(|| std::thread::spawn(f))
}

fn thread_start(
    init_thread: Box<
        dyn litebox::shim::InitThread<ExecutionContext = litebox_common_linux::PtRegs>,
    >,
    mut ctx: litebox_common_linux::PtRegs,
    vector_state: Box<litebox_common_linux::GuestVectorState>,
) {
    let shim = init_thread.init();
    run_thread_inner(
        shim.as_ref(),
        &mut ctx,
        GuestVectorStateMode::Inherited(vector_state),
    );
    // TODO: have syscall_callback return if we need to terminate the process.
    // We should return this value to the caller so load_program can return it
    // to the user.
}

// A handle to a platform thread.
#[derive(Clone)]
pub struct ThreadHandle(std::sync::Arc<std::sync::Mutex<Option<libc::pid_t>>>);

thread_local! {
    static CURRENT_THREAD: std::cell::RefCell<Option<ThreadHandle>> = const { std::cell::RefCell::new(None) };
}

/// Clears inherited guest-thread registration in the fork child, and hands the alternate signal
/// stack of the abandoned guest-thread call to the clone's next one.
///
/// # Panics
///
/// Panics if copied platform thread state is borrowed or poisoned.
///
/// # Safety
///
/// The caller must be the sole thread in a newly cloned process and must never return through the
/// copied guest-thread stack after calling this function.
pub unsafe fn reset_current_thread_after_process_clone() {
    // SAFETY: sole surviving clone thread; caller never resumes copied guards.
    unsafe {
        arch::reset_after_fork();
    }
    let current = CURRENT_THREAD.take();
    if let Some(current) = current {
        *current.0.lock().expect("thread handle mutex poisoned") = None;
    }
    if let SignalAltStack::Active(record) = SIGNAL_ALT_STACK.get() {
        SIGNAL_ALT_STACK.set(SignalAltStack::Orphaned(record));
    }
    replace_guest_thread_marker(false);
}

impl ThreadHandle {
    /// Runs `f`, ensuring that [`ThreadHandle::current`] can be called within `f`.
    fn run_with_handle<R>(f: impl FnOnce() -> R) -> R {
        // A raw clone does not update libc's cached pthread TID, so query the kernel directly.
        // SAFETY: gettid takes no arguments and always returns the calling thread's ID.
        let thread_id = unsafe { libc::syscall(libc::SYS_gettid) };
        let thread_id = libc::pid_t::try_from(thread_id).expect("kernel thread ID fits pid_t");
        let handle = ThreadHandle(std::sync::Arc::new(std::sync::Mutex::new(Some(thread_id))));
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
            // SAFETY: Holding the registration lock prevents the target from unregistering and
            // exiting, so its kernel TID cannot be reused before this directed signal is sent.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_tgkill,
                    libc::getpid(),
                    thread,
                    INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed),
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                // A full real-time signal queue means interrupts are already pending, and a
                // thread exiting outside its registration has nothing left to interrupt.
                assert!(
                    matches!(error.raw_os_error(), Some(libc::EAGAIN | libc::ESRCH)),
                    "failed to interrupt host thread {thread}: {error}"
                );
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
        let vector_state =
            Box::new(litebox::platform::GuestVectorStateProvider::get_guest_vector_state(self));
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new()
            .spawn(move || thread_start(init_thread, ctx, vector_state))?;

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
        // Sets `gsbase = fsbase` (x86_64) on the current thread
        // to mirror the TLS base used in guest context, so that test threads can use the
        // same TLS access code as guest threads.
        #[cfg(target_arch = "x86_64")]
        if GUEST_TLS_MODE.load(Ordering::Relaxed) == GuestTlsMode::Linux as u8 {
            unsafe {
                core::arch::asm!(
                    "rdfsbase {tmp}",
                    "wrgsbase {tmp}",
                    tmp = out(reg) _,
                    options(nostack, preserves_flags),
                );
            }
        }

        let _guest_thread = GuestThreadMarker::enter();

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

impl RawMutexProvider for LinuxUserland {
    type RawMutex = RawMutex;
}

impl WaitWakerProvider for LinuxUserland {
    fn update_waker(&self, waker: Option<core::task::Waker>) {
        let waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
        let waker_ptr = arch::swap_wait_waker_addr(waker_ptr as usize) as *mut core::task::Waker;
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

impl RawMutexTrait for RawMutex {
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

impl TimeProvider for LinuxUserland {
    type Instant = Instant;
    type SystemTime = SystemTime;

    fn now(&self) -> Self::Instant {
        let mut t = core::mem::MaybeUninit::<libc::timespec>::uninit();
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) };
        let t = unsafe { t.assume_init() };
        Instant {
            #[expect(clippy::useless_conversion)]
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
            #[expect(clippy::useless_conversion)]
            inner: Duration::new(
                t.tv_sec.reinterpret_as_unsigned().into(),
                t.tv_nsec.reinterpret_as_unsigned().trunc(),
            ),
        }
    }
}

impl litebox::platform::CpuTimeProvider for LinuxUserland {
    fn thread_cpu_time(&self) -> Option<litebox::platform::CpuTime> {
        host_cpu_time(libc::RUSAGE_THREAD)
    }

    fn process_cpu_time(&self) -> Option<litebox::platform::CpuTime> {
        host_cpu_time(libc::RUSAGE_SELF)
    }
}

/// Returns the CPU time the host reports for `who`, a `getrusage` target.
fn host_cpu_time(who: libc::c_int) -> Option<litebox::platform::CpuTime> {
    // SAFETY: A zeroed `rusage` is valid output storage for `getrusage`.
    let mut usage = unsafe { core::mem::zeroed::<libc::rusage>() };
    // SAFETY: `usage` is writable storage for one `rusage`.
    if unsafe { libc::getrusage(who, &raw mut usage) } != 0 {
        return None;
    }
    let duration = |time: libc::timeval| {
        Duration::from_secs(u64::try_from(time.tv_sec).ok()?)
            .checked_add(Duration::from_micros(u64::try_from(time.tv_usec).ok()?))
    };
    Some(litebox::platform::CpuTime {
        user: duration(usage.ru_utime)?,
        system: duration(usage.ru_stime)?,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    inner: Duration,
}

impl InstantTrait for Instant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<Duration> {
        self.inner.checked_sub(earlier.inner)
    }
    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        Some(Self {
            inner: self.inner.checked_add(duration)?,
        })
    }
    fn saturating_add(&self, duration: Duration) -> Self {
        Self {
            inner: self.inner.saturating_add(duration),
        }
    }
}

pub struct SystemTime {
    inner: Duration,
}

impl SystemTimeTrait for SystemTime {
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
            syscalls::Sysno::futex,
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

/// Whether `pc` is inside a sequence switching this thread to guest state.
///
/// From the store that sets `in_guest` to the final branch into the guest,
/// neither the host's nor the guest's register state is self-consistent, so a
/// signal arriving there must not be attributed to the guest; each caller
/// decides what to do instead.
///
/// AArch64 has two such sequences to x86-64's one, in separate functions, so
/// this is a union of two ranges: one span would depend on link order.
fn in_switch_to_guest(pc: usize) -> bool {
    arch::in_switch_to_guest(pc)
}

/// Whether `ip` is inside `syscall_callback`'s prologue, i.e. before the guest
/// has been fully accounted for but after control has left the guest.
///
/// This is `interrupt_signal_handler` case 1. Getting the bound wrong is not a
/// benign off-by-one: an `ip` past the bound but still before `in_guest` is
/// cleared falls through to case 4, where `copy_signal_context`
/// overwrites the guest `PtRegs` with *host* state — a runtime pc, the gate
/// frame's shifted sp, and `syscallno = NO_SYSCALL` — silently dropping the
/// in-flight guest syscall.
fn in_syscall_callback_prologue(ip: usize) -> bool {
    arch::in_syscall_callback_prologue(ip)
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
    #[cfg(target_arch = "x86_64")]
    let info = litebox::shim::ExceptionInfo {
        exception: litebox::shim::Exception(trapno.try_into().unwrap()),
        error_code: error.try_into().unwrap(),
        cr2,
        kernel_mode: false,
    };
    // On AArch64 the hardware trap number and error code are not visible to
    // userspace, so `exception_signal_handler` passes the signal number in
    // `trapno` and zero in `error`, and the exception class is recovered from
    // the signal.
    #[cfg(target_arch = "aarch64")]
    let info = {
        let _ = error;
        let exception = match i32::try_from(trapno).unwrap_or(0) {
            libc::SIGILL => litebox::shim::Exception::INSTRUCTION_ABORT_LOWER_EL,
            libc::SIGTRAP => litebox::shim::Exception::BRK64,
            // Everything else reaching this handler -- SIGSEGV, SIGBUS and
            // SIGFPE -- is reported as a data abort. SIGFPE does have a class
            // of its own, 0x2c, but the shim cannot deliver SIGFPE yet; see
            // its `handle_exception_request`.
            _ => litebox::shim::Exception::DATA_ABORT_LOWER_EL,
        };
        litebox::shim::ExceptionInfo {
            exception,
            fault_address: cr2,
            // The real ESR_EL1 is not exposed to userspace — the arm64 signal
            // frame carries no syndrome register — so synthesize one holding
            // just the exception class in bits 31:26. The instruction-specific
            // syndrome (ISS) bits 24:0 are unavoidably zero.
            esr: u64::from(exception.0) << 26,
            kernel_mode: false,
        }
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
        arch::clear_interrupt();
        let op = f(self.shim, self.ctx);
        match op {
            ContinueOperation::Resume => unsafe { switch_to_guest(self.ctx) },
            ContinueOperation::Terminate => {}
        }
    }
}

impl litebox::platform::SystemInfoProvider for LinuxUserland {
    fn get_syscall_entry_point(&self) -> usize {
        arch::syscall_entry_point()
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

    #[cfg(target_arch = "aarch64")]
    fn guest_thread_pointer_offset(&self) -> Option<usize> {
        arch::tp::guest_thread_pointer_offset()
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
            sa.sa_sigaction = interrupt_entry as *const () as usize;
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
                // Keep signal frames off gate scratch storage below guest SP.
                sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
                // `SA_NODEFER`: the gate classifier probes memory around a guest
                // PC that may be unmapped, and reaching the exception-table
                // fixup for that probe needs this handler to be re-entrant.
                // Without it the kernel force-kills on the nested fault, so a
                // guest jumping to a bad pointer would take the host with it.
                // Nothing on the x86-64 path probes guest memory, so leaving
                // the flag off there keeps the kernel's recursion backstop.
                #[cfg(target_arch = "aarch64")]
                {
                    sa.sa_flags |= libc::SA_NODEFER;
                }
                sa.sa_sigaction = exception_entry as *const () as usize;
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
                sa.sa_sigaction = interrupt_entry as *const () as usize;
                // Block the interrupt signal while handling signals
                libc::sigaddset(&raw mut sa.sa_mask, interrupt_signal);
                let mut old_sa = core::mem::zeroed();
                sigaction(sig, Some(&sa), &mut old_sa);
                // Launchers may hand down `SIG_IGN` (e.g., to background jobs). Replacing it is
                // fine because the guest's own disposition decides whether to ignore the signal.
                assert!(
                    old_sa.sa_sigaction == libc::SIG_DFL || old_sa.sa_sigaction == libc::SIG_IGN,
                    "signal {sig} handler already installed",
                );
            }
        }
    });
}

/// An anonymous read-write stack mapping with an inaccessible guard below it, which overflows of
/// the stack fault on. Dropping it unmaps the whole mapping.
struct GuardedStack(GuardedStackParts);

/// The mapping a [`GuardedStack`] owns, without ownership.
#[derive(Clone, Copy)]
struct GuardedStackParts {
    mapping: core::ptr::NonNull<libc::c_void>,
    guard_size: usize,
    size: usize,
}

impl GuardedStack {
    /// Maps `size` usable bytes above a `guard_size`-byte guard, both multiples of the page size.
    fn map(guard_size: usize, size: usize) -> std::io::Result<Self> {
        // SAFETY: An anonymous private mapping at a kernel-chosen address affects no existing
        // memory.
        let mapping = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                guard_size + size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let Some(mapping) = core::ptr::NonNull::new(mapping) else {
            return Err(std::io::Error::other("mmap returned a null stack"));
        };
        let stack = Self(GuardedStackParts {
            mapping,
            guard_size,
            size,
        });
        // SAFETY: The guard lies within the mapping this function just created.
        if unsafe { libc::mprotect(mapping.as_ptr(), guard_size, libc::PROT_NONE) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stack)
    }

    /// Takes ownership of the mapping `parts` describes.
    ///
    /// # Safety
    ///
    /// `parts` must describe a mapping a [`GuardedStack`] created, which nothing else owns.
    unsafe fn from_parts(parts: GuardedStackParts) -> Self {
        Self(parts)
    }

    /// Describes the mapping, without giving up ownership.
    fn parts(&self) -> GuardedStackParts {
        self.0
    }

    /// Lowest usable address, just above the guard.
    fn bottom(&self) -> *mut libc::c_void {
        self.0.mapping.as_ptr().wrapping_byte_add(self.0.guard_size)
    }

    /// Usable size, above the guard.
    fn size(&self) -> usize {
        self.0.size
    }
}

impl Drop for GuardedStack {
    fn drop(&mut self) {
        let GuardedStackParts {
            mapping,
            guard_size,
            size,
        } = self.0;
        // SAFETY: This value exclusively owns the mapping, which nothing runs on once it drops.
        let result = unsafe { libc::munmap(mapping.as_ptr(), guard_size + size) };
        assert_eq!(
            result,
            0,
            "failed to free memory for alternate signal stack: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// A [`with_signal_alt_stack`] call's alternate signal stack, and the stack it restores.
#[derive(Clone, Copy)]
struct SignalAltStackRecord {
    stack: GuardedStackParts,
    previous: libc::stack_t,
}

/// This thread's [`with_signal_alt_stack`] state.
#[derive(Clone, Copy, Default)]
enum SignalAltStack {
    #[default]
    None,
    /// Owned by a running [`with_signal_alt_stack`] call.
    Active(SignalAltStackRecord),
    /// Owned by a call whose frames a process clone abandoned, for the clone's next call to adopt.
    Orphaned(SignalAltStackRecord),
}

thread_local! {
    static SIGNAL_ALT_STACK: Cell<SignalAltStack> = const { Cell::new(SignalAltStack::None) };
}

/// Runs `f` with an alternate signal stack set up.
///
/// In a process clone, this adopts the stack the cloned thread had, so a fork chain keeps one.
fn with_signal_alt_stack<R>(f: impl FnOnce() -> R) -> R {
    let (stack, previous) = match SIGNAL_ALT_STACK.take() {
        SignalAltStack::None => {
            let stack = GuardedStack::map(0x1000, libc::SIGSTKSZ * 2).unwrap_or_else(|error| {
                panic!("failed to allocate memory for alternate signal stack: {error}")
            });
            let alt_stack = libc::stack_t {
                ss_sp: stack.bottom(),
                ss_flags: 0,
                ss_size: stack.size(),
            };
            let mut oss = libc::stack_t {
                ss_sp: std::ptr::null_mut(),
                ss_flags: 0,
                ss_size: 0,
            };
            // SAFETY: `alt_stack` describes the usable part of `stack`, which this call owns and
            // keeps mapped until it restores `oss`, and `oss` is writable.
            let r = unsafe { libc::sigaltstack(&raw const alt_stack, &raw mut oss) };
            assert!(
                r >= 0,
                "failed to set up alternate signal stack: {}",
                std::io::Error::last_os_error(),
            );
            (stack, oss)
        }
        // A process clone inherits its thread's alternate signal stack setting, so the adopted
        // stack is still installed. Restore what the call that mapped it replaced.
        SignalAltStack::Orphaned(record) => {
            // SAFETY: Only `reset_current_thread_after_process_clone` orphans a record, once the
            // call that owned its stack is abandoned, and taking it leaves this call the only owner.
            let stack = unsafe { GuardedStack::from_parts(record.stack) };
            (stack, record.previous)
        }
        SignalAltStack::Active(_) => panic!("nested with_signal_alt_stack calls are not supported"),
    };
    SIGNAL_ALT_STACK.set(SignalAltStack::Active(SignalAltStackRecord {
        stack: stack.parts(),
        previous,
    }));
    let _restore_guard = litebox::utils::defer(|| {
        SIGNAL_ALT_STACK.set(SignalAltStack::None);
        // SAFETY: `previous` is the setting `stack` replaced, and `stack` stays mapped until
        // after this guard drops.
        let r = unsafe { libc::sigaltstack(&raw const previous, std::ptr::null_mut()) };
        assert!(
            r >= 0,
            "failed to restore original signal stack: {}",
            std::io::Error::last_os_error()
        );
    });
    f()
}

#[cfg(target_arch = "aarch64")]
fn is_synchronous_memory_fault(signum: libc::c_int, code: libc::c_int) -> bool {
    match signum {
        // SEGV_MTEAERR (8) is asynchronous; the other currently defined
        // positive Linux SIGSEGV codes identify the faulting instruction.
        libc::SIGSEGV => (1..=7).contains(&code) || code == 9,
        // BUS_MCEERR_AO (5) is explicitly asynchronous.
        libc::SIGBUS => (1..=libc::BUS_MCEERR_AR).contains(&code),
        _ => false,
    }
}

#[cfg(target_arch = "aarch64")]
fn gate_interruption(signum: libc::c_int, code: libc::c_int) -> GateInterruption {
    if is_synchronous_memory_fault(signum, code) {
        GateInterruption::Synchronous
    } else if signum == libc::SIGTRAP && code == libc::TRAP_BRKPT {
        GateInterruption::Breakpoint
    } else {
        GateInterruption::Asynchronous
    }
}

/// Updates guest registers; returns true when the gate consumes the signal.
#[cfg(target_arch = "aarch64")]
fn update_aarch64_guest_signal_context(
    context: &libc::ucontext_t,
    regs: &mut litebox_common_linux::PtRegs,
    interruption: GateInterruption,
) -> bool {
    let (result, interrupted) =
        canonicalize_runtime_aarch64_gate_signal_context(context, regs, interruption);
    match result {
        Aarch64GateSignalResult::NotGate => *regs = interrupted,
        Aarch64GateSignalResult::Canonicalized(canonical) => *regs = canonical,
        Aarch64GateSignalResult::ResumeGuest(canonical) => {
            *regs = canonical;
            return true;
        }
        Aarch64GateSignalResult::PreserveSavedContext => {
            // Saved registers are authoritative, but the outbound stub leaves a stale syscall number.
            regs.syscallno = litebox_common_linux::arch::NO_SYSCALL;
        }
        Aarch64GateSignalResult::InvalidRuntimeState => fatal_aarch64_runtime_state(),
    }
    false
}

#[cfg(target_arch = "aarch64")]
fn signal_exception_fixup(signum: libc::c_int, code: libc::c_int, pc: usize) -> Option<usize> {
    is_synchronous_memory_fault(signum, code)
        .then(|| litebox::mm::exception_table::search_exception_tables(pc))
        .flatten()
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
    #[cfg(target_arch = "aarch64")] entry: arch::tp::SignalEntry,
) {
    #[cfg(target_arch = "aarch64")]
    let faulting_pc: usize = context.uc_mcontext.pc.trunc();
    #[cfg(target_arch = "x86_64")]
    let faulting_pc: usize = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .trunc();

    // Staging can raise SIGSEGV/SIGBUS with `in_guest` set; fix up before checking it.
    #[cfg(target_arch = "aarch64")]
    if let Some(fixup_addr) = signal_exception_fixup(signum, info.si_code, faulting_pc) {
        // The staging-store assembly fixup clears `in_guest` on resumption.
        context.uc_mcontext.pc = fixup_addr as u64;
        return;
    }

    #[cfg(target_arch = "aarch64")]
    {
        if arch::tp::SignalEntry::in_exception_prologue(faulting_pc) {
            if is_synchronous_memory_fault(signum, info.si_code) {
                fatal_aarch64_runtime_state();
            }
            // User-generated exception signals still belong to the host
            // disposition. Do not copy a wrapper/prologue PC/SP into guest state.
            if info.si_code <= 0 {
                return unsafe { next_signal_handler(signum, info, context) };
            }
            signal_handler_set_interrupt();
            return;
        }
        entry.capture_guest_tp(faulting_pc);
    }

    // Transition faults are host faults: `in_guest` and SP may be inconsistent.
    if in_switch_to_guest(faulting_pc) {
        return unsafe { next_signal_handler(signum, info, context) };
    }

    // Nested faults in the handler must be classified as host faults.
    #[cfg(target_arch = "aarch64")]
    let interrupted_guest = entry.take_guest();

    #[cfg(debug_assertions)]
    if signum == libc::SIGSYS {
        use core::fmt::Write as _;
        #[cfg(target_arch = "x86_64")]
        let (sysno, arg1) = {
            let sysno = context.uc_mcontext.gregs[libc::REG_RAX as usize];
            context.uc_mcontext.gregs[libc::REG_RAX as usize] = i64::from(-libc::EINVAL);
            (
                sysno,
                context.uc_mcontext.gregs[libc::REG_RSI as usize] as *const core::ffi::c_char,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let (sysno, arg1) = {
            let sysno = context.uc_mcontext.regs[8].cast_signed();
            context.uc_mcontext.regs[0] = i64::from(-libc::EINVAL).cast_unsigned();
            (
                sysno,
                context.uc_mcontext.regs[1] as *const core::ffi::c_char,
            )
        };
        // Signal-safe: format on the stack via arrayvec (no heap allocation).
        let mut buf = arrayvec::ArrayString::<320>::new();
        if sysno == libc::SYS_openat {
            let c_path = unsafe { core::ffi::CStr::from_ptr(arg1) };
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
        #[cfg(target_arch = "x86_64")]
        return;
        #[cfg(target_arch = "aarch64")]
        {
            // Resume through host code without re-arming `in_guest` here.
            if let Some(regs) = interrupted_guest {
                signal_handler_capture_guest_vector_state(context);
                update_aarch64_guest_signal_context(
                    context,
                    unsafe { &mut *regs },
                    gate_interruption(signum, info.si_code),
                );
                set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
            }
            return;
        }
    }

    #[cfg(target_arch = "x86_64")]
    let Some(regs) = signal_handler_exit_guest(context, false) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    #[cfg(target_arch = "aarch64")]
    let Some(regs) = interrupted_guest else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    #[cfg(target_arch = "x86_64")]
    copy_signal_context(unsafe { &mut *regs }, context);
    #[cfg(target_arch = "aarch64")]
    {
        signal_handler_capture_guest_vector_state(context);
        if update_aarch64_guest_signal_context(
            context,
            unsafe { &mut *regs },
            gate_interruption(signum, info.si_code),
        ) {
            set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
            return;
        }
    }

    let _ = run_thread_arch as *const () as usize;

    let sigctx = &context.uc_mcontext;
    #[cfg(target_arch = "x86_64")]
    let (trapno, err, cr2) = (
        sigctx.gregs[libc::REG_TRAPNO as usize].trunc(),
        sigctx.gregs[libc::REG_ERR as usize].trunc(),
        sigctx.gregs[libc::REG_CR2 as usize].trunc(),
    );
    // AArch64 exposes no trap number or error code to userspace, so the signal
    // number stands in for the trap and the error code is always zero;
    // `exception_handler` recovers an exception class from it. The four-argument
    // shape is kept so `exception_callback`'s x1/x2/x3 marshalling is shared.
    //
    // The fault address comes from `uc_mcontext.fault_address`, not
    // `siginfo.si_addr`. That field is what the arm64 kernel copies out of
    // `current->thread.fault_address`, i.e. FAR_EL1 — exactly what
    // `ExceptionInfo::fault_address` is documented to carry. `si_addr` is a
    // per-signal derived value and for SIGILL is the faulting *PC*, which
    // would put a program counter in a field named `fault_address`.
    #[cfg(target_arch = "aarch64")]
    let (trapno, err, cr2) = (
        // Widen infallibly: this runs in a signal handler, where a panic is
        // not async-signal-safe. `i64::from` is a lossless widening and
        // `trunc` to `isize` is exact on a 64-bit target.
        TruncateExt::<isize>::trunc(i64::from(signum)),
        0isize,
        TruncateExt::<usize>::trunc(sigctx.fault_address).reinterpret_as_signed(),
    );
    set_signal_return(context, exception_callback, 0, trapno, err, cr2);
}

/// Runs the next signal handler in the chain.
unsafe fn next_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    if signum == libc::SIGSEGV {
        let ip: usize = {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize]
                    .reinterpret_as_unsigned()
                    .trunc()
            }
            #[cfg(target_arch = "aarch64")]
            {
                context.uc_mcontext.pc.trunc()
            }
        };
        #[cfg(target_arch = "x86_64")]
        // TODO: Restrict x86-64 fixups to synchronous faults too; otherwise an
        // asynchronous SIGSEGV that interrupts a fixup range can be consumed.
        let fixup_addr = litebox::mm::exception_table::search_exception_tables(ip);
        #[cfg(target_arch = "aarch64")]
        let fixup_addr = signal_exception_fixup(signum, info.si_code, ip);
        if let Some(fixup_addr) = fixup_addr {
            #[cfg(target_arch = "x86_64")]
            {
                context.uc_mcontext.gregs[libc::REG_RIP as usize] =
                    fixup_addr.reinterpret_as_signed() as i64;
            }
            #[cfg(target_arch = "aarch64")]
            {
                context.uc_mcontext.pc = fixup_addr as u64;
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

/// Records a pending host signal in the TLS bitmask and wakes any condvar the
/// thread is blocked on.
///
/// # Safety
///
/// Must be called from a signal handler on a guest thread.
///
/// On x86-64, host TLS must be accessible through GS in Linux guest mode or
/// through FS in Windows guest mode.
unsafe fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let mask: u32 = 1u32 << (signal.as_i32() - 1);
    // SAFETY: the caller satisfies the architecture-specific TLS access
    // requirements documented above.
    let waker_addr = unsafe { arch::record_pending_signal(mask) };
    if waker_addr == 0 {
        return;
    }
    // SAFETY: if `waker_addr` is not zero, that means the current thread is suspended
    // to handle this signal and it points to a valid Waker whose lifetime spans the
    // entire interruptible wait, set by [`WaitWakerProvider::update_waker`].
    let waker = unsafe { &*(waker_addr as *const core::task::Waker) };
    waker.wake_by_ref();
}

/// Signal handler for interrupt signals.
unsafe fn interrupt_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
    #[cfg(target_arch = "aarch64")] entry: arch::tp::SignalEntry,
) {
    #[cfg(target_arch = "aarch64")]
    let interrupted_guest = entry.take_interrupted_guest(context.uc_mcontext.pc.trunc());

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

        if let Ok(signal) = litebox_common_linux::signal::Signal::try_from(guest_signum) {
            // Check whether this is a guest thread. If not, re-raise the signal
            // process-wide.
            if is_guest_thread_from_signal_context() {
                // SAFETY: we verified above that this is a guest thread.
                unsafe { record_pending_signal(signal) };
            } else {
                #[cfg(debug_assertions)]
                raise_signal(signum, info);
                return;
            }
        } else {
            // Unknown signals are dropped, but aarch64 has already cleared `in_guest`:
            // an interrupted guest must exit through `interrupt_callback`.
            #[cfg(target_arch = "x86_64")]
            return;
            #[cfg(target_arch = "aarch64")]
            if interrupted_guest.is_none() {
                return;
            }
        }
    }

    // Note that this signal can't arrive while in an exception signal handler
    // since we mask the interrupt signal while handling exceptions.

    #[cfg(target_arch = "x86_64")]
    let ip = context.uc_mcontext.gregs[libc::REG_RIP as usize]
        .reinterpret_as_unsigned()
        .trunc();
    #[cfg(target_arch = "aarch64")]
    let ip = context.uc_mcontext.pc.trunc();

    // FUTURE: handle trampoline code, too. This is somewhat less important
    // because it's probably fine for the shim to observe a guest context that
    // is inside the trampoline.
    if in_syscall_callback_prologue(ip) {
        return;
    }

    let in_switch_to_guest = in_switch_to_guest(ip);
    #[cfg(target_arch = "x86_64")]
    let Some(regs) = signal_handler_exit_guest(context, true) else {
        return;
    };
    #[cfg(target_arch = "aarch64")]
    signal_handler_set_interrupt();
    #[cfg(target_arch = "aarch64")]
    // No guest to resume: the signal interrupted host code or a signal transition.
    let Some(regs) = interrupted_guest else {
        return;
    };
    #[cfg(target_arch = "aarch64")]
    if !in_switch_to_guest {
        signal_handler_capture_guest_vector_state(context);
    }

    if in_switch_to_guest {
        // The saved guest context remains authoritative during restoration.
    } else {
        #[cfg(target_arch = "x86_64")]
        copy_signal_context(unsafe { &mut *regs }, context);
        #[cfg(target_arch = "aarch64")]
        update_aarch64_guest_signal_context(
            context,
            unsafe { &mut *regs },
            GateInterruption::Asynchronous,
        );
    }
    // Cases 3 and 4: jump to interrupt handler.
    #[cfg(target_arch = "x86_64")]
    let callback = if in_switch_to_guest {
        interrupt_callback_no_xsave
    } else {
        interrupt_callback
    };
    #[cfg(target_arch = "aarch64")]
    let callback = interrupt_callback;
    set_signal_return(context, callback, 0, 0, 0, 0);
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

    fn compute_with_derived_key<E, const KEY_LEN: usize>(
        &self,
        root: litebox::platform::RootKey,
        shim_kdf: fn(&[u8], litebox::platform::KDFParams) -> Result<(), E>,
        key_context: &[u8],
        op: fn(&[u8], litebox::platform::ComputeParams) -> Result<(), E>,
        params: litebox::platform::ComputeParams,
    ) -> Result<(), litebox::platform::DerivedKeyError<E>> {
        // Only per-boot keys: the boot ID changes on every reboot.
        if root != litebox::platform::RootKey::PerBoot {
            return Err(litebox::platform::DerivedKeyError::UnsupportedRebootPersistentKey);
        }
        let Some(boot_id) = self.boot_id.get() else {
            return Err(litebox::platform::DerivedKeyError::UnsupportedPerBootKey);
        };
        let mut key = [0u8; KEY_LEN];
        shim_kdf(
            boot_id,
            litebox::platform::KDFParams {
                context: key_context,
                output: &mut key,
            },
        )?;
        Ok(op(&key, params)?)
    }
}

/// Dummy `VmapManager`.
///
/// In general, userland platforms do not support `vmap` and `vunmap` (which are kernel functions).
/// We might need to emulate these functions' behaviors using virtual addresses for development or
/// testing, or use a kernel module to provide this functionality (if needed).
unsafe impl<const ALIGN: usize> VmapManager<ALIGN> for LinuxUserland {
    type MapInfo = litebox::mm::vmap::NoopPhysPageMapInfo;

    fn validate_unowned(
        &self,
        _pages: &litebox::mm::vmap::PhysPageAddrArray<ALIGN>,
    ) -> Result<(), litebox::mm::vmap::PhysPointerError> {
        Err(litebox::mm::vmap::PhysPointerError::UnsupportedOperation)
    }

    unsafe fn protect(
        &self,
        _pages: &litebox::mm::vmap::PhysPageAddrArray<ALIGN>,
        _perms: litebox::mm::vmap::PhysPageMapPermissions,
    ) -> Result<(), litebox::mm::vmap::PhysPointerError> {
        Err(litebox::mm::vmap::PhysPointerError::UnsupportedOperation)
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
    use core::sync::atomic::AtomicU32;
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::thread::sleep;

    use litebox_common_linux::OFlags;
    use litebox_platform::sync::RawMutex;

    use crate::LinuxUserland;

    extern crate std;

    // Re-exec exactly one test to isolate raw clone, signal actions, table
    // exhaustion and TSYNC from unrelated harness threads and allocator locks.
    // Returns true in the parent, where the test has already run in the child.
    pub(crate) fn reexec_test_if_needed(name: &str) -> bool {
        const CHILD: &str = "LITEBOX_PLATFORM_TEST_CHILD";
        if std::env::var(CHILD).ok().as_deref() == Some(name) {
            return false;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, name)
            .output()
            .unwrap();
        assert!(output.status.success(), "{name}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
        true
    }

    #[test]
    fn native_clone_thread_can_be_interrupted() {
        if reexec_test_if_needed("tests::native_clone_thread_can_be_interrupted") {
            return;
        }
        // SAFETY: A null stack creates a fork-like clone. Only the child uses the copied
        // runtime below, and it exits without returning through the test harness.
        let child = unsafe {
            libc::syscall(
                libc::SYS_clone,
                libc::SIGCHLD,
                0usize,
                core::ptr::null_mut::<libc::pid_t>(),
                core::ptr::null_mut::<libc::pid_t>(),
                0usize,
            )
        };
        assert!(
            child >= 0,
            "clone failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            // SAFETY: The child is the only surviving thread and never returns to copied state.
            unsafe { super::reset_current_thread_after_process_clone() };
            super::INTERRUPT_SIGNAL_NUMBER
                .store(libc::SIGUSR1, core::sync::atomic::Ordering::Relaxed);
            // SAFETY: A zero-initialized sigset_t is valid storage for sigemptyset.
            let mut signals = unsafe { core::mem::zeroed::<libc::sigset_t>() };
            // SAFETY: `signals` is writable, and pthread_sigmask copies it before returning.
            let blocked = unsafe {
                libc::sigemptyset(&raw mut signals) == 0
                    && libc::sigaddset(&raw mut signals, libc::SIGUSR1) == 0
                    && libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const signals,
                        core::ptr::null_mut(),
                    ) == 0
            };
            let interrupted = blocked
                && super::ThreadHandle::run_with_handle(|| {
                    let thread = super::ThreadHandle::current();
                    let Ok(sender) = std::thread::Builder::new().spawn(move || thread.interrupt())
                    else {
                        return false;
                    };
                    let timeout = libc::timespec {
                        tv_sec: 2,
                        tv_nsec: 0,
                    };
                    // SAFETY: The signal is blocked in both threads, and the set and timeout
                    // are valid for the bounded wait. No signal handler runs in the child.
                    let signal = unsafe {
                        libc::sigtimedwait(
                            &raw const signals,
                            core::ptr::null_mut(),
                            &raw const timeout,
                        )
                    };
                    sender.join().is_ok() && signal == libc::SIGUSR1
                });
            // SAFETY: Do not unwind through or destroy the copied test runtime.
            unsafe { libc::_exit(i32::from(!interrupted)) };
        }
        let child = libc::pid_t::try_from(child).expect("clone returned a valid process ID");
        let mut status = 0;
        loop {
            // SAFETY: This test owns the clone, and `status` is writable.
            let waited = unsafe { libc::waitpid(child, &raw mut status, 0) };
            if waited == child {
                break;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR),
                "waitpid failed"
            );
        }
        assert!(
            libc::WIFEXITED(status),
            "clone did not exit normally: {status}"
        );
        assert_eq!(libc::WEXITSTATUS(status), 0, "clone was not interrupted");
    }

    #[test]
    fn process_clone_adopts_the_alternate_signal_stack_it_inherited() {
        const MAPPED_NEW_STACK: i32 = 1;
        const DID_NOT_RESTORE_PREDECESSOR: i32 = 2;
        const KEPT_ADOPTED_STACK_MAPPED: i32 = 3;
        fn current_alt_stack() -> *mut libc::c_void {
            // SAFETY: A zeroed stack_t is valid output storage for sigaltstack.
            let mut current = unsafe { core::mem::zeroed::<libc::stack_t>() };
            // SAFETY: A null new stack only queries the current one into `current`.
            assert_eq!(
                unsafe { libc::sigaltstack(core::ptr::null(), &raw mut current) },
                0
            );
            current.ss_sp
        }
        fn is_mapped(address: *mut libc::c_void) -> bool {
            // SAFETY: `msync` only queries the page, which it rejects with ENOMEM if unmapped.
            unsafe { libc::msync(address, 1, libc::MS_ASYNC) == 0 }
        }

        let predecessor = current_alt_stack();
        super::with_signal_alt_stack(|| {
            let inherited = current_alt_stack();
            // SAFETY: A null stack creates a fork-like clone. Only the child uses the copied
            // runtime below, and it exits without returning through the test harness.
            let child = unsafe {
                libc::syscall(
                    libc::SYS_clone,
                    libc::SIGCHLD,
                    0usize,
                    core::ptr::null_mut::<libc::pid_t>(),
                    core::ptr::null_mut::<libc::pid_t>(),
                    0usize,
                )
            };
            assert!(
                child >= 0,
                "clone failed: {}",
                std::io::Error::last_os_error()
            );
            if child == 0 {
                // SAFETY: The child is the only surviving thread and never returns to copied
                // state.
                unsafe { super::reset_current_thread_after_process_clone() };
                let adopted = super::with_signal_alt_stack(|| current_alt_stack() == inherited);
                let code = if !adopted {
                    MAPPED_NEW_STACK
                } else if current_alt_stack() != predecessor {
                    DID_NOT_RESTORE_PREDECESSOR
                } else if is_mapped(inherited) {
                    KEPT_ADOPTED_STACK_MAPPED
                } else {
                    0
                };
                // SAFETY: Do not unwind through or destroy the copied test runtime.
                unsafe { libc::_exit(code) };
            }
            let child = libc::pid_t::try_from(child).expect("clone returned a valid process ID");
            let mut status = 0;
            // SAFETY: This test owns the clone, and `status` is writable.
            while unsafe { libc::waitpid(child, &raw mut status, 0) } != child {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR),
                    "waitpid failed"
                );
            }
            let failure = match libc::WIFEXITED(status).then(|| libc::WEXITSTATUS(status)) {
                Some(0) => return,
                Some(MAPPED_NEW_STACK) => "the clone mapped a new alternate signal stack",
                Some(DID_NOT_RESTORE_PREDECESSOR) => {
                    "the clone did not restore the stack the parent's call replaced"
                }
                Some(KEPT_ADOPTED_STACK_MAPPED) => "the clone did not unmap the adopted stack",
                _ => "the clone did not exit normally",
            };
            panic!("{failure} (status {status:#x})");
        });
    }

    /// An interrupt pending at guest entry diverts to the interrupt handler
    /// without entering the guest, so a further interrupt taken while that
    /// handler runs host code must not be treated as a guest interrupt, which
    /// would re-enter the handler.
    #[test]
    fn interrupt_in_diverted_interrupt_handler_is_not_a_guest_interrupt() {
        use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
        use litebox_common_linux::PtRegs;

        // The signal is delivered to the calling thread before `pthread_kill` returns.
        fn interrupt_current_thread() {
            let signal = super::INTERRUPT_SIGNAL_NUMBER.load(core::sync::atomic::Ordering::Relaxed);
            // SAFETY: `pthread_self` is a live thread with the interrupt handler installed.
            assert_eq!(
                unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                0
            );
        }

        #[derive(Default)]
        struct Shim {
            interrupts: core::cell::Cell<u32>,
        }

        impl EnterShim for Shim {
            type ExecutionContext = PtRegs;

            fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                interrupt_current_thread();
                ContinueOperation::Resume
            }

            fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                unreachable!()
            }

            fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
                self.interrupts.set(self.interrupts.get() + 1);
                if self.interrupts.get() == 1 {
                    interrupt_current_thread();
                }
                ContinueOperation::Terminate
            }
        }

        let _platform = LinuxUserland::new();
        let shim = Shim::default();
        // SAFETY: the shim terminates the thread before it enters the guest.
        unsafe { super::run_thread_ref(&shim, &mut PtRegs::default()) };
        assert_eq!(shim.interrupts.get(), 1);
    }

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
    fn test_seccomp_filter() {
        fn test_memfd(name: &std::ffi::CStr) -> OwnedFd {
            // SAFETY: `name` is a valid C string and the returned descriptor is
            // transferred immediately into `OwnedFd`.
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0);
            // SAFETY: `fd` was just returned as an owned descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        if reexec_test_if_needed("tests::test_seccomp_filter") {
            return;
        }
        let _platform: &LinuxUserland = LinuxUserland::new();
        let allowed = test_memfd(c"seccomp-allowed-positional-io");
        let denied = test_memfd(c"seccomp-denied-positional-io");
        let (allowed_shutdown, _allowed_peer) = UnixStream::pair().unwrap();
        let (denied_shutdown, _denied_peer) = UnixStream::pair().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = barrier.clone();
        // Spawned before the filter is installed.
        let worker = super::spawn_host_thread(move || {
            worker_barrier.wait();
            worker_barrier.wait();
            assert_seccomp_filter();
        });
        barrier.wait();
        LinuxUserland::enable_seccomp_filter(
            &[allowed.as_raw_fd()],
            &[allowed_shutdown.as_raw_fd()],
            super::SeccompScope::AllThreads,
            None,
            None,
        );
        barrier.wait();

        let written = [7_u8];
        // SAFETY: The buffers are valid for their lengths, and both descriptors
        // remain open for the calls.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    allowed.as_raw_fd(),
                    written.as_ptr().cast(),
                    written.len(),
                    0,
                )
            },
            1
        );
        let mut read = [0_u8];
        // SAFETY: See the `pwrite` call above.
        assert_eq!(
            unsafe { libc::pread(allowed.as_raw_fd(), read.as_mut_ptr().cast(), read.len(), 0,) },
            1
        );
        assert_eq!(read, written);
        // SAFETY: See the allowed `pwrite` call above.
        assert_eq!(
            unsafe {
                libc::pwrite(
                    denied.as_raw_fd(),
                    written.as_ptr().cast(),
                    written.len(),
                    0,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINVAL)
        );
        let error = allowed_shutdown.shutdown(Shutdown::Write).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        allowed_shutdown.shutdown(Shutdown::Both).unwrap();
        let error = denied_shutdown.shutdown(Shutdown::Both).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));

        assert_seccomp_filter();
        worker.join().unwrap();
    }

    fn assert_seccomp_filter() {
        let pathname = c"/tmp/test_seccomp";
        #[cfg(target_arch = "x86_64")]
        let mkdir_res = unsafe {
            syscalls::syscall2(syscalls::Sysno::mkdir, pathname.as_ptr() as usize, 0o755)
        };
        #[cfg(target_arch = "aarch64")]
        let mkdir_res = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mkdirat,
                super::AT_FDCWD,
                pathname.as_ptr() as usize,
                0o755,
            )
        };
        assert_eq!(
            mkdir_res.unwrap_err(),
            syscalls::Errno::EINVAL,
            "mkdir/mkdirat should be blocked by seccomp filter"
        );

        let pathname =
            std::ffi::CString::new(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))).unwrap();

        // The runner opens no host files, so even a read-only open is denied.
        for flags in [OFlags::RDONLY, OFlags::RDWR] {
            #[cfg(target_arch = "x86_64")]
            let open_res = unsafe {
                syscalls::syscall2(
                    syscalls::Sysno::open,
                    pathname.as_ptr() as usize,
                    flags.bits() as usize,
                )
            };
            #[cfg(target_arch = "aarch64")]
            let open_res = unsafe {
                syscalls::syscall4(
                    syscalls::Sysno::openat,
                    super::AT_FDCWD,
                    pathname.as_ptr() as usize,
                    flags.bits() as usize,
                    0,
                )
            };
            assert_eq!(
                open_res.unwrap_err(),
                syscalls::Errno::EINVAL,
                "open with {flags:?} should be blocked by seccomp filter"
            );
        }
    }
}
