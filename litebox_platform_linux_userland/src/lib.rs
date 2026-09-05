// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A [LiteBox platform](../litebox/platform/index.html) for running LiteBox on userland Linux.

#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::time::Duration;
use std::unimplemented;

use litebox::fs::OFlags;
use litebox::platform::RawConstPointer as _;
use litebox::platform::page_mgmt::{
    CowAllocationError, FixedAddressBehavior, MemoryRegionPermissions,
};
use litebox::shim::ContinueOperation;
use litebox::utils::{ReinterpretSignedExt, ReinterpretUnsignedExt as _, TruncateExt};
use litebox_common_linux::{MRemapFlags, MapFlags, ProtFlags, vmap::VmapManager};
use litebox_platform::sync::{
    ImmediatelyWokenUp, RawMutex as RawMutexTrait, RawMutexProvider, UnblockedOrTimedOut,
    WaitWakerProvider,
};

use zerocopy::{FromBytes, IntoBytes};

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(test, target_arch = "aarch64"))]
use aarch64::get_guest_vector_state;
#[cfg(target_arch = "aarch64")]
use aarch64::{
    Aarch64GateSignalResult, GateInterruption, assert_tls_block_placement,
    canonicalize_runtime_aarch64_gate_signal_context, copy_signal_context,
    fatal_aarch64_runtime_state, guest_thread_pointer_tp_offset, is_guest_thread,
    load_tls_block_base, run_thread_arch, set_guest_vector_state, set_is_guest_thread,
    set_signal_return, signal_handler_exit_guest, switch_to_guest, sync_instruction_stream,
    tls_offset,
};

extern crate alloc;

#[cfg(target_arch = "aarch64")]
const AT_FDCWD: usize = (litebox_common_linux::AT_FDCWD as isize).cast_unsigned();

/// The admitted open syscall and its flags index must remain paired.
#[cfg(target_arch = "x86_64")]
const OPEN_SYSNO: i64 = libc::SYS_open;
#[cfg(target_arch = "x86_64")]
const OPEN_FLAGS_ARG: u8 = 1;
#[cfg(target_arch = "aarch64")]
const OPEN_SYSNO: i64 = libc::SYS_openat;
#[cfg(target_arch = "aarch64")]
const OPEN_FLAGS_ARG: u8 = 2;

// ---------------------------------------------------------------------------
// TLS (`.tbss`) access helpers
//
// On x86_64, the ELF TLS model uses `@tpoff`; on x86 it uses `@ntpoff`.
// At guest-host transitions we swap `fs` and `gs`, so after the swap the host TLS base
// is in the normal segment register. Before the swap (e.g. in a signal
// handler that fires while the guest is running), the host TLS base is
// in the *saved* segment register (`gs` on x86_64, `fs` on x86).
//
// The macros below produce string literals so they can be used inside
// `concat!()` within `core::arch::asm!()`.
// ---------------------------------------------------------------------------

/// TLS relocation suffix: `"@tpoff"` on x86_64, `"@ntpoff"` on x86.
#[cfg(target_arch = "x86_64")]
macro_rules! tls_suffix {
    () => {
        "@tpoff"
    };
}

/// Segment register used for TLS after the fs/gs swap (normal host context).
#[cfg(target_arch = "x86_64")]
macro_rules! tls_seg {
    () => {
        "fs"
    };
}

/// Segment register where the host TLS base is saved before the swap
/// (signal handler context while the guest is running).
#[cfg(target_arch = "x86_64")]
macro_rules! saved_tls_seg {
    () => {
        "gs"
    };
}

/// Full TLS memory operand for a `.tbss` variable in normal host context
/// (after the fs/gs swap).
///
/// Example: `tls!("pending_host_signals")` expands to
/// `"fs:pending_host_signals@tpoff"` on x86_64.
#[cfg(target_arch = "x86_64")]
macro_rules! tls {
    ($var:literal) => {
        concat!(tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// Full TLS memory operand for a `.tbss` variable accessed via the *saved*
/// segment register (before the fs/gs swap, e.g. from a signal handler).
///
/// Example: `saved_tls!("in_guest")` expands to
/// `"gs:in_guest@tpoff"` on x86_64.
#[cfg(target_arch = "x86_64")]
macro_rules! saved_tls {
    ($var:literal) => {
        concat!(saved_tls_seg!(), ":", $var, tls_suffix!())
    };
}

/// The userland Linux platform.
///
/// This implements the main [`litebox::platform::Provider`] trait, i.e., implements all platform
/// traits.
pub struct LinuxUserland {
    /// Reserved pages that are not available for guest programs to use.
    reserved_pages: Vec<core::ops::Range<usize>>,
    /// CoW-eligible memory regions. Maps start address of the static slice, to the info needed to
    /// re-mmap the file.
    cow_regions: std::sync::RwLock<std::collections::BTreeMap<usize, CowRegionInfo>>,
    /// If [`Self::initialize_boot_specific_kdf_support`] has been run, this is set to a value that
    /// is persistent across multiple process executions, however, it is ephemeral across true
    /// reboots.
    boot_id: std::sync::OnceLock<Vec<u8>>,
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

impl LinuxUserland {
    /// Create a new userland-Linux platform for use in `LiteBox`.
    pub fn new() -> &'static Self {
        #[cfg(target_arch = "aarch64")]
        assert_tls_block_placement();

        register_exception_handlers();

        let reserved_pages = Self::read_maps();
        let platform = Self {
            reserved_pages,
            cow_regions: std::sync::RwLock::new(std::collections::BTreeMap::new()),
            boot_id: std::sync::OnceLock::new(),
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

    fn read_maps() -> alloc::vec::Vec<core::ops::Range<usize>> {
        // TODO: this function is not guaranteed to return all allocated pages, as it may
        // allocate more pages after the mapping file is read. Missing allocated pages may
        // cause the program to crash when calling `mmap` or `mremap` with the `MAP_FIXED` flag later.
        // We should either fix `mmap` to handle this error, or let global allocator call this function
        // whenever it get more pages from the host.
        let path = c"/proc/self/maps";
        #[cfg(target_arch = "x86_64")]
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                path.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
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
        unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) }.expect("close failed");

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

    #[allow(
        clippy::missing_panics_doc,
        reason = "the seccomp filter rules are hardcoded and not expected to fail"
    )]
    /// Installs the runner seccomp filter.
    ///
    /// Broker transport exceptions are restricted to the supplied descriptors.
    pub fn enable_seccomp_filter(
        positional_io_fds: &[std::os::fd::RawFd],
        shutdown_fds: &[std::os::fd::RawFd],
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
            //
            // A mismatched syscall and flags index would admit arbitrary flags.
            (
                OPEN_SYSNO,
                vec![
                    SeccompRule::new(vec![
                        SeccompCondition::new(
                            OPEN_FLAGS_ARG,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(OFlags::RDONLY.bits()),
                        )
                        .unwrap(),
                    ])
                    .unwrap(),
                ],
            ),
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
        if !positional_io_fds.is_empty() {
            // Broker shared memory uses positional descriptor I/O.
            let fd_rules = || {
                positional_io_fds
                    .iter()
                    .map(|fd| {
                        SeccompRule::new(vec![
                            SeccompCondition::new(
                                0,
                                SeccompCmpArgLen::Dword,
                                SeccompCmpOp::Eq,
                                u64::from(
                                    u32::try_from(*fd)
                                        .expect("positional I/O descriptor must be valid"),
                                ),
                            )
                            .unwrap(),
                        ])
                        .unwrap()
                    })
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
                        SeccompCondition::new(
                            0,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(
                                u32::try_from(*fd).expect("shutdown descriptor must be valid"),
                            ),
                        )
                        .unwrap(),
                        SeccompCondition::new(
                            1,
                            SeccompCmpArgLen::Dword,
                            SeccompCmpOp::Eq,
                            u64::from(
                                u32::try_from(libc::SHUT_RDWR)
                                    .expect("SHUT_RDWR must be non-negative"),
                            ),
                        )
                        .unwrap(),
                    ])
                    .unwrap()
                })
                .collect();
            rules.push((libc::SYS_shutdown, shutdown_rules));
        }
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
            if cfg!(target_arch = "x86_64") {
                seccompiler::TargetArch::x86_64
            } else {
                seccompiler::TargetArch::aarch64
            },
        )
        .unwrap();
        // TODO: bpf program can be compiled offline
        let bpf_prog: BpfProgram = filter.try_into().unwrap();

        seccompiler::apply_filter(&bpf_prog).unwrap();
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
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            "xor {tmp:e}, {tmp:e}",
            concat!("xchg DWORD PTR ", tls!("pending_host_signals"), ", {tmp:e}"),
            tmp = out(reg) lo,
            options(nostack)
        );
    }
    // Atomic against this thread's signal handlers; use the ARMv8.0 baseline
    // rather than ARMv8.1 LSE.
    #[cfg(target_arch = "aarch64")]
    // SAFETY: reads and clears a naturally aligned `u32` in this thread's own
    // TLS control block, whose offset from `TPIDR_EL0` is checked by
    // `assert_tls_block_placement`.
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{addr}"),
            "add {addr}, {addr}, #{off}",
            "2:",
            "ldaxr {val:w}, [{addr}]",
            "stlxr {status:w}, wzr, [{addr}]",
            "cbnz {status:w}, 2b",
            addr = out(reg) _,
            val = out(reg) lo,
            status = out(reg) _,
            off = const tls_offset::PENDING_HOST_SIGNALS,
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
    run_thread_inner(&shim, ctx, false);
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
    run_thread_inner(shim, ctx, false);
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
    run_thread_inner(shim, ctx, true);
}

struct ThreadContext<'a> {
    shim: &'a dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &'a mut litebox_common_linux::PtRegs,
}

fn run_thread_inner(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = litebox_common_linux::PtRegs>,
    ctx: &mut litebox_common_linux::PtRegs,
    reenter: bool,
) {
    let ctx_ptr = core::ptr::from_mut(ctx);
    let mut thread_ctx = ThreadContext { shim, ctx };
    let _guest_thread = GuestThreadMarker::enter();
    ThreadHandle::run_with_handle(|| {
        with_signal_alt_stack(|| unsafe {
            run_thread_arch(&mut thread_ctx, ctx_ptr, u8::from(reenter));
        });
    });
}

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    "
    .section .tbss
    .align 8
scratch:
    .quad 0
host_sp:
    .quad 0
host_bp:
    .quad 0
guest_context_top:
    .quad 0
.globl guest_fsbase
guest_fsbase:
    .quad 0
in_guest:
    .byte 0
.globl interrupt
interrupt:
    .byte 0
    .align 4
.globl pending_host_signals
pending_host_signals:
    .long 0
    .align 8
.globl wait_waker_addr
wait_waker_addr:
    .quad 0
    "
);

#[cfg(target_arch = "x86_64")]
fn set_guest_fsbase(value: usize) {
    unsafe {
        core::arch::asm! {
            "mov fs:guest_fsbase@tpoff, {}",
            in(reg) value,
            options(nostack, preserves_flags)
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn get_guest_fsbase() -> usize {
    let value: usize;
    unsafe {
        core::arch::asm! {
            "mov {}, fs:guest_fsbase@tpoff",
            out(reg) value,
            options(nostack, preserves_flags)
        }
    }
    value
}

/// Tracks the whole guest-thread lifetime on AArch64 and preserves nested-entry
/// state. On x86-64, `gsbase` provides the marker.
struct GuestThreadMarker {
    #[cfg(target_arch = "aarch64")]
    previous: bool,
}

impl GuestThreadMarker {
    fn enter() -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            Self {}
        }
        #[cfg(target_arch = "aarch64")]
        {
            let previous = is_guest_thread();
            set_is_guest_thread(true);
            Self { previous }
        }
    }
}

impl Drop for GuestThreadMarker {
    fn drop(&mut self) {
        #[cfg(target_arch = "aarch64")]
        set_is_guest_thread(self.previous);
    }
}

/// Runs the guest thread until it terminates.
///
/// This saves all non-volatile register state then switches to the guest
/// context. When the guest makes a syscall, it jumps back into the middle of
/// this routine, at `syscall_callback`. This code then updates the guest
/// context structure, switches back to the host stack, and calls the syscall
/// handler.
///
/// When the guest thread terminates, this function returns after restoring
/// non-volatile register state.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C-unwind" fn run_thread_arch(
    thread_ctx: &mut ThreadContext,
    ctx: *mut litebox_common_linux::PtRegs,
    reenter: u8,
) {
    core::arch::naked_asm!(
    "
    .cfi_startproc
    // Push all non-volatiles.
    push rbp
    mov rbp, rsp
    .cfi_def_cfa rbp, 16
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi // save thread context

    // Save host rsp and rbp and guest context top in TLS.
    mov fs:host_sp@tpoff, rsp
    mov fs:host_bp@tpoff, rbp
    lea r8, [rsi + {GUEST_CONTEXT_SIZE}]
    mov fs:guest_context_top@tpoff, r8

    // Save host fs base in gs base. This will stay set for the lifetime
    // of this call stack.
    rdfsbase r8
    wrgsbase r8

    // Call init_handler or reenter_handler based on reenter flag (in dl).
    test dl, dl
    jnz 1f
    call {init_handler}
    jmp .Ldone
1:
    call {reenter_handler}
    jmp .Ldone

    // This entry point is called from the guest when it issues a syscall
    // instruction.
    //
    // At entry, the register context is the guest context with the
    // return address in rcx. r11 is an available scratch register (it would
    // contain rflags if the syscall instruction had actually been issued).
    .globl syscall_callback
syscall_callback:
    // Clear in_guest flag. This must be the first instruction to match the
    // expectations of `interrupt_signal_handler`.
    mov      BYTE PTR gs:in_guest@tpoff, 0

    // Restore host fs base.
    rdfsbase r11
    mov      gs:guest_fsbase@tpoff, r11
    rdgsbase r11
    wrfsbase r11

    // Switch to the top of the guest context.
    mov     r11, rsp
    mov     rsp, fs:guest_context_top@tpoff

    // TODO: save float and vector registers (xsave or fxsave)
    // Save caller-saved registers
    push    0x2b       // pt_regs->ss = __USER_DS
    push    r11        // pt_regs->sp
    pushfq             // pt_regs->eflags
    push    0x33       // pt_regs->cs = __USER_CS
    push    rcx        // pt_regs->ip
    push    rax        // pt_regs->orig_ax

    push    rdi         // pt_regs->di
    push    rsi         // pt_regs->si
    push    rdx         // pt_regs->dx
    push    rcx         // pt_regs->cx
    push    -38         // pt_regs->ax = ENOSYS
    push    r8          // pt_regs->r8
    push    r9          // pt_regs->r9
    push    r10         // pt_regs->r10
    push    [rsp + 88]  // pt_regs->r11 = rflags
    push    rbx         // pt_regs->bx
    push    rbp         // pt_regs->bp
    push    r12         // pt_regs->r12
    push    r13         // pt_regs->r13
    push    r14         // pt_regs->r14
    push    r15         // pt_regs->r15

    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    // Handle the syscall. This will jump back to the guest but
    // will return if the thread is exiting.
    mov rdi, [rsp] // pass thread_ctx
    call {syscall_handler}
    // This thread is done. Return.
    jmp .Ldone

exception_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {exception_handler}
    jmp .Ldone

interrupt_callback:
    // Restore the stack and frame pointer.
    mov     rsp, fs:host_sp@tpoff
    mov     rbp, fs:host_bp@tpoff

    mov rdi, [rsp] // pass thread_ctx
    call {interrupt_handler}

.Ldone:

    lea  rsp, [rbp - 5*8]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    .cfi_def_cfa rsp, 8
    ret
    .cfi_endproc
",
    GUEST_CONTEXT_SIZE = const core::mem::size_of::<litebox_common_linux::PtRegs>(),
    init_handler = sym init_handler,
    reenter_handler = sym reenter_handler,
    syscall_handler = sym syscall_handler,
    exception_handler = sym exception_handler,
    interrupt_handler = sym interrupt_handler,
    );
}

/// Switches to the provided guest context.
///
/// # Safety
/// The context must be valid guest context. This can only be called if
/// `run_thread_arch` is on the stack; after the guest exits, it will return to
/// the interior of `run_thread_arch`.
///
/// Do not call this at a point where the stack needs to be unwound to run
/// destructors.
#[cfg(target_arch = "x86_64")]
#[unsafe(naked)]
unsafe extern "C" fn switch_to_guest(ctx: &litebox_common_linux::PtRegs) -> ! {
    core::arch::naked_asm!(
        "switch_to_guest_start:",
        // Set `in_guest` now, then check if there is a pending interrupt. If
        // so, jump to the interrupt handler.
        //
        // If an interrupt arrives after the check, then the signal handler will
        // see that the IP is between `switch_to_guest_start` and
        // `switch_to_guest_end` and will set the `interrupt` and jump to
        // `interrupt_callback`.
        "mov BYTE PTR fs:in_guest@tpoff, 1",
        "cmp BYTE PTR fs:interrupt@tpoff, 0",
        "jne interrupt_callback",
        // Restore guest context from ctx.
        "mov rsp, rdi",
        // Switch to the guest fsbase
        "mov rdx, fs:guest_fsbase@tpoff",
        "wrfsbase rdx",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rax",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 8",           // skip orig_rax
        "pop gs:scratch@tpoff", // read rip into scratch
        "add rsp, 8",           // skip cs
        "popfq",
        "pop rsp",
        "jmp gs:scratch@tpoff", // jump to the guest
        "switch_to_guest_end:",
    );
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
    #[cfg(target_arch = "aarch64")] vector_state: litebox_common_linux::GuestVectorState,
) {
    #[cfg(target_arch = "aarch64")]
    set_guest_vector_state(&vector_state);
    // Allow caller to run some code before we return to the new thread.
    let shim = init_thread.init();

    run_thread_inner(shim.as_ref(), &mut ctx, false);
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
        #[cfg(target_arch = "aarch64")]
        let vector_state =
            litebox::platform::GuestVectorStateProvider::get_guest_vector_state(self);
        // TODO: do we need to wait for the handle in the main thread?
        let _handle = std::thread::Builder::new().spawn(move || {
            thread_start(
                init_thread,
                ctx,
                #[cfg(target_arch = "aarch64")]
                vector_state,
            );
        })?;

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
        let mut waker_ptr = waker.map_or(std::ptr::null_mut(), |w| Box::into_raw(Box::new(w)));
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                concat!("xchg ", tls!("wait_waker_addr"), ", {}"),
                inout(reg) waker_ptr,
                options(nostack),
            );
        }
        // Atomic against `record_pending_signal` in this thread's handler.
        #[cfg(target_arch = "aarch64")]
        // SAFETY: exchanges a naturally aligned `u64` in this thread's own TLS
        // control block, whose offset from `TPIDR_EL0` is checked by
        // `assert_tls_block_placement`.
        unsafe {
            let new_ptr = waker_ptr;
            core::arch::asm!(
                load_tls_block_base!("{addr}"),
                "add {addr}, {addr}, #{off}",
                "2:",
                "ldaxr {old}, [{addr}]",
                "stlxr {status:w}, {new}, [{addr}]",
                "cbnz {status:w}, 2b",
                addr = out(reg) _,
                old = out(reg) waker_ptr,
                new = in(reg) new_ptr,
                status = out(reg) _,
                off = const tls_offset::WAIT_WAKER_ADDR,
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

impl litebox::platform::TimeProvider for LinuxUserland {
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

#[cfg(target_arch = "x86_64")]
impl litebox::platform::ArchSpecificProvider for LinuxUserland {
    // We swap gs and fs before and after a syscall, so while handling a guest
    // syscall the guest's fs base is stored in the gs base register; the
    // per-thread `guest_fsbase` slot holds the value that will be programmed
    // into fs base on guest re-entry.
    fn set_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
        val: usize,
    ) -> Result<(), litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => {
                if litebox_common_linux::arch::is_valid_user_fs_base(val) {
                    set_guest_fsbase(val);
                    Ok(())
                } else {
                    Err(litebox::platform::ArchSpecificError::RegisterUnpermittedValue)
                }
            }
            litebox::platform::ArchSpecificRegister::GsBase => {
                // GS base is used internally by this platform to hold the host
                // TLS base across the guest/host fs-gs swap, so it is not
                // directly programmable by the guest.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
    }
    fn get_arch_specific_register(
        &self,
        reg: &litebox::platform::ArchSpecificRegister,
    ) -> Result<usize, litebox::platform::ArchSpecificError> {
        match reg {
            litebox::platform::ArchSpecificRegister::FsBase => Ok(get_guest_fsbase()),
            litebox::platform::ArchSpecificRegister::GsBase => {
                // See note above: gs base is reserved for host TLS on this
                // platform and is not exposed to the guest.
                Err(litebox::platform::ArchSpecificError::RegisterReserved)
            }
            _ => Err(litebox::platform::ArchSpecificError::RegisterUnsupported),
        }
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

#[cfg(target_arch = "aarch64")]
fn cache_sync_permissions(permissions: MemoryRegionPermissions) -> MemoryRegionPermissions {
    (permissions | MemoryRegionPermissions::READ) & !MemoryRegionPermissions::EXEC
}

impl<const ALIGN: usize> litebox::platform::PageManagementProvider<ALIGN> for LinuxUserland {
    const TASK_ADDR_MIN: usize = 0x1_0000; // default linux config
    #[cfg(target_arch = "x86_64")]
    const TASK_ADDR_MAX: usize = 0x7FFF_FFFF_F000; // (1 << 47) - PAGE_SIZE;
    /// Assumes the host kernel is configured for a 48-bit user virtual address
    /// space. AArch64 Linux is also built with 39, 42 and 47 bits, and on those
    /// hosts this hands out addresses the kernel then refuses to map.
    ///
    /// Naming the smallest configuration instead is not an option today: the
    /// allocator in `litebox::mm` searches downwards from the highest existing
    /// mapping, and the runtime's own mappings sit above any limit smaller than
    /// the host's real one, leaving it unable to place anything at all.
    ///
    /// TODO: probe the host's limit -- this is an associated const, so that
    /// needs `PageManagementProvider` to express a runtime bound -- and teach
    /// the allocator to place into a region holding no existing mapping.
    #[cfg(target_arch = "aarch64")]
    const TASK_ADDR_MAX: usize = 0x0000_FFFF_FFFF_F000; // (1 << 48) - PAGE_SIZE;

    fn allocate_pages(
        &self,
        suggested_range: core::ops::Range<usize>,
        initial_permissions: MemoryRegionPermissions,
        can_grow_down: bool,
        populate_pages_immediately: bool,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::AllocationError> {
        let flags = MapFlags::MAP_PRIVATE
            | MapFlags::MAP_ANONYMOUS
            | match fixed_address_behavior {
                FixedAddressBehavior::Hint => MapFlags::empty(),
                FixedAddressBehavior::Replace => MapFlags::MAP_FIXED,
                FixedAddressBehavior::NoReplace => MapFlags::MAP_FIXED_NOREPLACE,
            }
            | if can_grow_down {
                MapFlags::MAP_GROWSDOWN
            } else {
                MapFlags::empty()
            }
            | if populate_pages_immediately {
                MapFlags::MAP_POPULATE
            } else {
                MapFlags::empty()
            };
        let r = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                suggested_range.start,
                suggested_range.len(),
                prot_flags(initial_permissions)
                    .bits()
                    .reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                usize::MAX,
                0,
            )
        };
        let ptr = r.map_err(|err| match err {
            syscalls::Errno::ENOMEM => litebox::platform::page_mgmt::AllocationError::OutOfMemory,
            syscalls::Errno::EEXIST => {
                assert!(matches!(
                    fixed_address_behavior,
                    FixedAddressBehavior::NoReplace
                ));
                litebox::platform::page_mgmt::AllocationError::AddressInUse
            }
            _ => panic!("unhandled mmap error {err}"),
        })?;
        Ok(UserMutPtr::from_usize(ptr))
    }

    unsafe fn deallocate_pages(
        &self,
        range: core::ops::Range<usize>,
    ) -> Result<(), litebox::platform::page_mgmt::DeallocationError> {
        let _ = unsafe { syscalls::syscall2(syscalls::Sysno::munmap, range.start, range.len()) }
            .expect("munmap failed");
        Ok(())
    }

    unsafe fn remap_pages(
        &self,
        old_range: core::ops::Range<usize>,
        new_range: core::ops::Range<usize>,
        _permissions: MemoryRegionPermissions,
    ) -> Result<Self::RawMutPointer<u8>, litebox::platform::page_mgmt::RemapError> {
        let res = unsafe {
            syscalls::syscall5(
                syscalls::Sysno::mremap,
                old_range.start,
                old_range.len(),
                new_range.len(),
                MRemapFlags::MREMAP_MAYMOVE.bits() as usize,
                new_range.start,
            )
            .expect("mremap failed")
        };
        Ok(UserMutPtr::from_usize(res))
    }

    unsafe fn update_permissions(
        &self,
        range: core::ops::Range<usize>,
        new_permissions: MemoryRegionPermissions,
    ) -> Result<(), litebox::platform::page_mgmt::PermissionUpdateError> {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            syscalls::syscall3(
                syscalls::Sysno::mprotect,
                range.start,
                range.len(),
                prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
            )
        }
        .expect("mprotect failed");

        #[cfg(target_arch = "aarch64")]
        {
            // Cache maintenance needs read permission. Keep execute disabled until
            // the new instructions are visible to the fetch path.
            //
            // TODO: only a W->X transition needs this; `update_permissions` is not
            // told the old permissions, so every transition to X pays for it.
            // Revisit when the trait passes the old permissions.
            let syncing = new_permissions.contains(MemoryRegionPermissions::EXEC);
            let mapped_permissions = if syncing {
                cache_sync_permissions(new_permissions)
            } else {
                new_permissions
            };

            unsafe {
                syscalls::syscall3(
                    syscalls::Sysno::mprotect,
                    range.start,
                    range.len(),
                    prot_flags(mapped_permissions)
                        .bits()
                        .reinterpret_as_unsigned() as usize,
                )
            }
            .expect("mprotect failed");
            if syncing {
                sync_instruction_stream(range.clone());
                if mapped_permissions != new_permissions {
                    unsafe {
                        syscalls::syscall3(
                            syscalls::Sysno::mprotect,
                            range.start,
                            range.len(),
                            prot_flags(new_permissions).bits().reinterpret_as_unsigned() as usize,
                        )
                    }
                    .expect("mprotect failed");
                }
            }
        }
        Ok(())
    }

    fn reserved_pages(&self) -> impl Iterator<Item = &core::ops::Range<usize>> {
        self.reserved_pages.iter()
    }

    fn try_allocate_cow_pages(
        &self,
        suggested_start: usize,
        source_data: &'static [u8],
        permissions: MemoryRegionPermissions,
        fixed_address_behavior: FixedAddressBehavior,
    ) -> Result<Self::RawMutPointer<u8>, CowAllocationError> {
        let Some((file_path, file_offset)) = self.lookup_cow_region(source_data) else {
            return Err(CowAllocationError::UnsupportedSourceRegion);
        };
        if !file_offset.is_multiple_of(ALIGN) {
            return Err(CowAllocationError::Unaligned);
        }

        let file_path_cstr =
            std::ffi::CString::new(file_path.as_os_str().as_encoded_bytes()).unwrap();
        // TODO(jb): We should likely be storing pre-opened FDs, right?
        #[cfg(target_arch = "x86_64")]
        let fd = unsafe {
            syscalls::syscall3(
                syscalls::Sysno::open,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let fd = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                AT_FDCWD,
                file_path_cstr.as_ptr() as usize,
                OFlags::RDONLY.bits() as usize,
                0,
            )
        };
        let fd = fd.expect("file should remain unchanged on host");

        let mut flags = MapFlags::MAP_PRIVATE;
        match fixed_address_behavior {
            FixedAddressBehavior::Hint => {}
            FixedAddressBehavior::Replace => flags |= MapFlags::MAP_FIXED,
            FixedAddressBehavior::NoReplace => flags |= MapFlags::MAP_FIXED_NOREPLACE,
        }

        let result = unsafe {
            syscalls::syscall6(
                syscalls::Sysno::mmap,
                suggested_start,
                source_data.len(),
                prot_flags(permissions).bits().reinterpret_as_unsigned() as usize,
                flags.bits().reinterpret_as_unsigned() as usize,
                fd,
                file_offset,
            )
        };

        let _ = unsafe { syscalls::syscall1(syscalls::Sysno::close, fd) };

        match result {
            Ok(ptr) => Ok(UserMutPtr::from_usize(ptr)),
            Err(_) => Err(CowAllocationError::InternalFailure),
        }
    }
}

unsafe extern "C" {
    fn syscall_callback() -> isize;
    #[cfg(target_arch = "aarch64")]
    fn syscall_callback_in_guest_cleared();
    fn exception_callback();
    fn interrupt_callback();
    #[cfg(target_arch = "x86_64")]
    fn switch_to_guest_start();
    #[cfg(target_arch = "x86_64")]
    fn switch_to_guest_end();
    #[cfg(target_arch = "aarch64")]
    fn switch_to_guest_via_outbound_stub_start();
    #[cfg(target_arch = "aarch64")]
    fn switch_to_guest_via_outbound_stub_end();
    #[cfg(target_arch = "aarch64")]
    fn switch_to_guest_via_sigreturn_start();
    #[cfg(target_arch = "aarch64")]
    fn switch_to_guest_via_sigreturn_end();
    #[cfg(all(test, target_arch = "aarch64"))]
    fn switch_to_guest_stage_x16();
    #[cfg(all(test, target_arch = "aarch64"))]
    fn switch_to_guest_stage_x16_fixup();
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
    fn body(start: unsafe extern "C" fn(), end: unsafe extern "C" fn()) -> core::ops::Range<usize> {
        start as *const () as usize..end as *const () as usize
    }

    #[cfg(target_arch = "x86_64")]
    {
        body(switch_to_guest_start, switch_to_guest_end).contains(&pc)
    }
    #[cfg(target_arch = "aarch64")]
    {
        body(
            switch_to_guest_via_outbound_stub_start,
            switch_to_guest_via_outbound_stub_end,
        )
        .contains(&pc)
            || body(
                switch_to_guest_via_sigreturn_start,
                switch_to_guest_via_sigreturn_end,
            )
            .contains(&pc)
    }
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
    let start = syscall_callback as *const () as usize;
    #[cfg(target_arch = "x86_64")]
    {
        ip == start
    }
    // The label keeps the multi-instruction AArch64 bound tied to the asm.
    #[cfg(target_arch = "aarch64")]
    {
        (start..syscall_callback_in_guest_cleared as *const () as usize).contains(&ip)
    }
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
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                concat!("mov BYTE PTR ", tls!("interrupt"), ", 0"),
                options(nostack, preserves_flags)
            );
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: writes a single byte in this thread's own TLS control block.
        unsafe {
            core::arch::asm!(
                load_tls_block_base!("{tmp}"),
                "strb wzr, [{tmp}, #{off}]",
                tmp = out(reg) _,
                off = const tls_offset::INTERRUPT,
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

    #[cfg(target_arch = "aarch64")]
    fn guest_thread_pointer_offset(&self) -> Option<usize> {
        Some(guest_thread_pointer_tp_offset().into())
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

/// Called from signal handlers to fix up thread state after potentially running
/// in the guest.
///
/// Restores the proper host `fsbase` so that TLS can be used. Clears `in_guest`
/// and optionally sets `interrupt`. If `in_guest` was previously set, returns
/// the guest context pointer (which does not necessarily have up-to-date guest
/// register state yet).
#[cfg(target_arch = "x86_64")]
fn signal_handler_exit_guest(
    _context: &libc::ucontext_t,
    set_interrupt: bool,
    _capture_vector_state: bool,
) -> Option<*mut litebox_common_linux::PtRegs> {
    unsafe {
        let gsbase: u64;
        core::arch::asm! {
            "rdgsbase {}", out(reg) gsbase
        };
        let is_in_guest = if gsbase == 0 {
            false
        } else {
            let in_guest: u8;
            core::arch::asm! {
                "mov {in_guest}, BYTE PTR gs:in_guest@tpoff",
                "mov BYTE PTR gs:in_guest@tpoff, 0",
                in_guest = out(reg_byte) in_guest,
                options(nostack, preserves_flags)
            }
            if set_interrupt {
                core::arch::asm! {
                    "mov BYTE PTR gs:interrupt@tpoff, 1",
                    options(nostack, preserves_flags)
                };
            }
            in_guest != 0
        };
        if !is_in_guest {
            return None;
        }

        let guest_context_top: *mut litebox_common_linux::PtRegs;
        core::arch::asm! {
            "wrfsbase {gsbase}",
            "mov {guest_context_top}, fs:guest_context_top@tpoff",
            gsbase = in(reg) gsbase,
            guest_context_top = out(reg) guest_context_top,
            options(nostack, preserves_flags)
        };
        Some(guest_context_top.sub(1))
    }
}

/// Copies register state from a Linux signal context to a LiteBox PtRegs
/// structure.
#[cfg(target_arch = "x86_64")]
fn copy_signal_context(regs: &mut litebox_common_linux::PtRegs, context: &libc::ucontext_t) {
    let litebox_common_linux::PtRegs {
        r15,
        r14,
        r13,
        r12,
        rbp,
        rbx,
        r11,
        r10,
        r9,
        r8,
        rax,
        rcx,
        rdx,
        rsi,
        rdi,
        orig_rax,
        rip,
        cs: _,
        eflags,
        rsp,
        ss: _,
    } = regs;
    for (reg, sig_reg) in [
        (r15, libc::REG_R15),
        (r14, libc::REG_R14),
        (r13, libc::REG_R13),
        (r12, libc::REG_R12),
        (rbp, libc::REG_RBP),
        (rbx, libc::REG_RBX),
        (r11, libc::REG_R11),
        (r10, libc::REG_R10),
        (r9, libc::REG_R9),
        (r8, libc::REG_R8),
        (rax, libc::REG_RAX),
        (rcx, libc::REG_RCX),
        (rdx, libc::REG_RDX),
        (rsi, libc::REG_RSI),
        (rdi, libc::REG_RDI),
        (rip, libc::REG_RIP),
        (rsp, libc::REG_RSP),
        (eflags, libc::REG_EFL),
    ] {
        *reg = context.uc_mcontext.gregs[sig_reg.reinterpret_as_unsigned() as usize]
            .reinterpret_as_unsigned()
            .trunc();
    }
    *orig_rax = *rax;
}

/// Updates a Linux signal context to return to `f` with the given arguments.
#[cfg(target_arch = "x86_64")]
fn set_signal_return(
    context: &mut libc::ucontext_t,
    f: unsafe extern "C" fn(),
    p0: isize,
    p1: isize,
    p2: isize,
    p3: isize,
) {
    let sigctx = &mut context.uc_mcontext;
    sigctx.gregs[libc::REG_RIP as usize] = (f as usize).reinterpret_as_signed() as i64;
    sigctx.gregs[libc::REG_RDI as usize] = p0 as i64;
    sigctx.gregs[libc::REG_RSI as usize] = p1 as i64;
    sigctx.gregs[libc::REG_RDX as usize] = p2 as i64;
    sigctx.gregs[libc::REG_RCX as usize] = p3 as i64;
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

#[cfg(target_arch = "aarch64")]
fn signal_exception_fixup(signum: libc::c_int, code: libc::c_int, pc: usize) -> Option<usize> {
    is_synchronous_memory_fault(signum, code)
        .then(|| litebox::mm::exception_table::search_exception_tables(pc))
        .flatten()
}

/// Signal handler for hardware exceptions (SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP).
unsafe extern "C" fn exception_signal_handler(
    signum: libc::c_int,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
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
        return;
    }

    // Classify runtime transition faults before guest faults; misclassification
    // would disclose the live host register file through guest `PtRegs`.
    #[cfg(target_arch = "aarch64")]
    let faulting_pc: usize = context.uc_mcontext.pc.trunc();

    // The staging store is inside the `in_guest` bracket and may raise SIGSEGV
    // or SIGBUS, so its fixup must run before consulting `in_guest`.
    #[cfg(target_arch = "aarch64")]
    if let Some(fixup_addr) = signal_exception_fixup(signum, info.si_code, faulting_pc) {
        context.uc_mcontext.pc = fixup_addr as u64;
        return;
    }

    // Remaining faults inside the transition bracket are runtime faults and
    // cannot safely resume because `in_guest` and SP may be inconsistent.
    #[cfg(target_arch = "aarch64")]
    if in_switch_to_guest(faulting_pc) {
        return unsafe { next_signal_handler(signum, info, context) };
    }

    let Some(regs) = signal_handler_exit_guest(context, false, true) else {
        return unsafe { next_signal_handler(signum, info, context) };
    };
    #[cfg(target_arch = "x86_64")]
    copy_signal_context(unsafe { &mut *regs }, context);
    #[cfg(target_arch = "aarch64")]
    {
        let interruption = gate_interruption(signum, info.si_code);
        let mut resume_guest = false;
        match canonicalize_runtime_aarch64_gate_signal_context(
            context,
            unsafe { &*regs },
            interruption,
        ) {
            Aarch64GateSignalResult::NotGate => copy_signal_context(unsafe { &mut *regs }, context),
            Aarch64GateSignalResult::Canonicalized(canonical) => unsafe { regs.write(canonical) },
            Aarch64GateSignalResult::ResumeGuest(canonical) => {
                unsafe { regs.write(canonical) };
                resume_guest = true;
            }
            Aarch64GateSignalResult::PreserveSavedContext => {
                // The saved registers are already authoritative, but the
                // outbound stub retains the completed syscall number. Clear it
                // before exposing this context to exception handling.
                unsafe { (*regs).syscallno = litebox_common_linux::arch::NO_SYSCALL };
            }
            Aarch64GateSignalResult::InvalidRuntimeState => {
                fatal_aarch64_runtime_state();
            }
        }

        if resume_guest {
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
/// On x86-64 that additionally requires the thread's saved host TLS segment
/// register (`gsbase`) to be valid, since the bitmask is reached through it.
unsafe fn record_pending_signal(signal: litebox_common_linux::signal::Signal) {
    let mask: u32 = 1u32 << (signal.as_i32() - 1);
    let waker_addr: usize;

    // SAFETY: the bitmask and waker slot are reached through this thread's own
    // saved host TLS segment, which the caller guarantees is valid, and both
    // accesses are naturally aligned.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!(
            concat!("lock or DWORD PTR ", saved_tls!("pending_host_signals"), ", {mask:e}"),
            mask = in(reg) mask,
            options(nostack)
        );
        core::arch::asm!(
            concat!("mov {}, ", saved_tls!("wait_waker_addr")),
            out(reg) waker_addr,
            options(nostack, preserves_flags)
        );
    }

    // Atomic against an interrupted exchange; a plain load/or/store can lose a bit.
    //
    // SAFETY: both slots are in this thread's own TLS control block at offsets
    // checked by `assert_tls_block_placement`, and both accesses are naturally aligned.
    // The exclusive monitor reservation is opened and closed within the loop.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!(
            load_tls_block_base!("{block}"),
            "add {addr}, {block}, #{pending_off}",
            "2:",
            "ldaxr {old:w}, [{addr}]",
            "orr {new:w}, {old:w}, {mask:w}",
            "stlxr {status:w}, {new:w}, [{addr}]",
            "cbnz {status:w}, 2b",
            "ldr {waker}, [{block}, #{waker_off}]",
            block = out(reg) _,
            addr = out(reg) _,
            old = out(reg) _,
            new = out(reg) _,
            status = out(reg) _,
            waker = out(reg) waker_addr,
            mask = in(reg) mask,
            pending_off = const tls_offset::PENDING_HOST_SIGNALS,
            waker_off = const tls_offset::WAIT_WAKER_ADDR,
            options(nostack)
        );
    }

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

        // Check whether this is a guest thread. If not, re-raise the signal
        // process-wide.
        //
        // This is a thread-lifetime property, not `in_guest`: `in_guest` is 0
        // whenever a guest thread sits in the host, including parked in an
        // interruptible wait -- the case `record_pending_signal` and
        // `wait_waker_addr` serve.
        let is_guest_thread;
        #[cfg(target_arch = "x86_64")]
        {
            let gsbase: u64;
            unsafe { core::arch::asm!("rdgsbase {}", out(reg) gsbase) };
            is_guest_thread = gsbase != 0;
        }
        #[cfg(target_arch = "aarch64")]
        {
            is_guest_thread = self::is_guest_thread();
        }

        if is_guest_thread {
            // SAFETY: we verified above that this is a guest thread, which is
            // what `record_pending_signal` requires.
            unsafe { record_pending_signal(signal) };
        } else {
            #[cfg(debug_assertions)]
            raise_signal(signum, info);
            return;
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
    let Some(regs) = signal_handler_exit_guest(context, true, !in_switch_to_guest) else {
        return;
    };

    if in_switch_to_guest {
        // The saved guest context remains authoritative during restoration.
    } else {
        #[cfg(target_arch = "x86_64")]
        copy_signal_context(unsafe { &mut *regs }, context);
        #[cfg(target_arch = "aarch64")]
        match canonicalize_runtime_aarch64_gate_signal_context(
            context,
            unsafe { &*regs },
            GateInterruption::Asynchronous,
        ) {
            Aarch64GateSignalResult::NotGate => copy_signal_context(unsafe { &mut *regs }, context),
            Aarch64GateSignalResult::Canonicalized(canonical)
            | Aarch64GateSignalResult::ResumeGuest(canonical) => unsafe { regs.write(canonical) },
            Aarch64GateSignalResult::PreserveSavedContext => {
                // The outbound path preserves registers but leaves stale syscall state.
                unsafe { (*regs).syscallno = litebox_common_linux::arch::NO_SYSCALL };
            }
            Aarch64GateSignalResult::InvalidRuntimeState => {
                fatal_aarch64_runtime_state();
            }
        }
    }
    set_signal_return(context, interrupt_callback, 0, 0, 0, 0);
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
/// Provided to satisfy trait bounds for `PageManager::handle_page_fault`.
impl litebox::mm::linux::VmemPageFaultHandler for LinuxUserland {
    unsafe fn handle_page_fault(
        &self,
        _fault_addr: usize,
        _flags: litebox::mm::linux::VmFlags,
        _error_code: u64,
    ) -> Result<(), litebox::mm::linux::PageFaultError> {
        unreachable!("host kernel handles page faults for Linux userland")
    }

    fn access_error(_error_code: u64, _flags: litebox::mm::linux::VmFlags) -> bool {
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

    use litebox::fs::OFlags;
    use litebox_platform::sync::RawMutex;

    use crate::LinuxUserland;
    use litebox::platform::PageManagementProvider;

    extern crate std;

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn spawned_thread_installs_inherited_vector_state() {
        use litebox::platform::{GuestVectorStateProvider as _, ThreadProvider as _};
        use litebox::shim::{ContinueOperation, EnterShim, InitThread};

        struct ObserveInit(std::sync::mpsc::Sender<litebox_common_linux::GuestVectorState>);
        struct TerminateShim;

        impl InitThread for ObserveInit {
            type ExecutionContext = litebox_common_linux::PtRegs;

            fn init(
                self: Box<Self>,
            ) -> Box<dyn EnterShim<ExecutionContext = Self::ExecutionContext>> {
                self.0.send(super::get_guest_vector_state()).unwrap();
                Box::new(TerminateShim)
            }
        }

        impl EnterShim for TerminateShim {
            type ExecutionContext = litebox_common_linux::PtRegs;

            fn init(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
                ContinueOperation::Terminate
            }

            fn syscall(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
                unreachable!()
            }

            fn exception(
                &self,
                _ctx: &mut Self::ExecutionContext,
                _info: &litebox::shim::ExceptionInfo,
            ) -> ContinueOperation {
                unreachable!()
            }

            fn interrupt(&self, _ctx: &mut Self::ExecutionContext) -> ContinueOperation {
                unreachable!()
            }
        }

        let platform = LinuxUserland::new();
        let original = platform.get_guest_vector_state();
        let expected = litebox_common_linux::GuestVectorState {
            registers: core::array::from_fn(|index| index as u128 * 0x101),
            fpsr: 0x1234,
            fpcr: 0x5678,
        };
        platform.set_guest_vector_state(&expected);
        let (send, receive) = std::sync::mpsc::channel();
        unsafe {
            platform
                .spawn_thread(
                    &litebox_common_linux::PtRegs::default(),
                    Box::new(ObserveInit(send)),
                )
                .unwrap();
        }
        let observed = receive
            .recv_timeout(core::time::Duration::from_secs(5))
            .unwrap();
        platform.set_guest_vector_state(&original);
        assert_eq!(observed, expected);
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn cache_sync_permissions_are_readable_and_non_executable() {
        use litebox::platform::page_mgmt::MemoryRegionPermissions;

        let final_permissions = MemoryRegionPermissions::READ | MemoryRegionPermissions::EXEC;
        let sync_permissions = super::cache_sync_permissions(final_permissions);

        assert!(sync_permissions.contains(MemoryRegionPermissions::READ));
        assert!(!sync_permissions.contains(MemoryRegionPermissions::EXEC));
        assert!(final_permissions.contains(MemoryRegionPermissions::EXEC));
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
    fn test_reserved_pages() {
        let platform = LinuxUserland::new();
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
    fn test_seccomp_filter() {
        fn test_memfd(name: &std::ffi::CStr) -> OwnedFd {
            // SAFETY: `name` is a valid C string and the returned descriptor is
            // transferred immediately into `OwnedFd`.
            let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0);
            // SAFETY: `fd` was just returned as an owned descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        }

        let _platform: &LinuxUserland = LinuxUserland::new();
        let allowed = test_memfd(c"seccomp-allowed-positional-io");
        let denied = test_memfd(c"seccomp-denied-positional-io");
        let (allowed_shutdown, _allowed_peer) = UnixStream::pair().unwrap();
        let (denied_shutdown, _denied_peer) = UnixStream::pair().unwrap();
        LinuxUserland::enable_seccomp_filter(
            &[allowed.as_raw_fd()],
            &[allowed_shutdown.as_raw_fd()],
        );

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

        // Denying RDWR does not on its own show that the rule reads the flags
        // argument: were it to read the path pointer instead, that too would
        // compare unequal to `O_RDONLY` and be denied. Only an allowed RDONLY
        // open pins the argument index `OPEN_FLAGS_ARG`.
        #[cfg(target_arch = "aarch64")]
        {
            let open_rdonly = unsafe {
                syscalls::syscall4(
                    syscalls::Sysno::openat,
                    super::AT_FDCWD,
                    pathname.as_ptr() as usize,
                    OFlags::RDONLY.bits() as usize,
                    0,
                )
            };
            let fd = open_rdonly.expect("openat with RDONLY should be allowed by seccomp filter");
            // SAFETY: the open above just returned this as a fresh owned descriptor.
            drop(unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) });
        }

        #[cfg(target_arch = "x86_64")]
        let open_res = unsafe {
            syscalls::syscall2(
                syscalls::Sysno::open,
                pathname.as_ptr() as usize,
                OFlags::RDWR.bits() as usize,
            )
        };
        #[cfg(target_arch = "aarch64")]
        let open_res = unsafe {
            syscalls::syscall4(
                syscalls::Sysno::openat,
                super::AT_FDCWD,
                pathname.as_ptr() as usize,
                OFlags::RDWR.bits() as usize,
                0,
            )
        };
        assert_eq!(
            open_res.unwrap_err(),
            syscalls::Errno::EINVAL,
            "open with RDWR should be blocked by seccomp filter"
        );
    }
}
