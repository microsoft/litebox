// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Thin bindings to the Darwin interfaces that have no `libc` crate coverage or
//! no direct POSIX equivalent.
//!
//! Everything here is either a documented libSystem entry point or a stable
//! kernel ABI. The `__ulock_*` family is the exception: it is not in a public
//! header, but it is the primitive libdispatch, libc++ and Rust's own standard
//! library have used for the same purpose for years, and it is the only
//! compare-and-wait facility available on every Apple Silicon release. The
//! public `os_sync_wait_on_address` alternative only exists from macOS 14.4,
//! which would leave earlier M-series machines with no implementation at all.

use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;

/// `MAP_JIT` from `<sys/mman.h>`: an anonymous mapping that may hold executable
/// code the process also writes to, subject to the per-thread write protection
/// toggled by [`pthread_jit_write_protect_np`].
pub(crate) const MAP_JIT: libc::c_int = 0x0800;

pub(crate) const KERN_SUCCESS: libc::c_int = 0;
pub(crate) const KERN_NO_SPACE: libc::c_int = 3;

/// `VM_FLAGS_FIXED`: allocate exactly at the requested address, failing with
/// `KERN_NO_SPACE` rather than relocating.
pub(crate) const VM_FLAGS_FIXED: libc::c_int = 0x0000;

/// `VM_FLAGS_OVERWRITE`: for [`mach_vm_remap`], replace whatever is already
/// mapped at the destination instead of failing if it's occupied.
///
/// TODO: this value (0x4000, matching XNU's `osfmk/mach/vm_statistics.h`
/// layout of the `VM_FLAGS_*` bit space as of this writing) was not
/// independently re-verified against a fetched copy of that header the way
/// the rest of this file's constants were -- confirm it before relying on
/// [`remap_to_fixed`] for anything beyond a best-effort implementation. A
/// wrong value fails safely (`mach_vm_remap` rejects an unrecognized flag
/// combination with a `KERN_*` error rather than silently doing the wrong
/// thing), but should still be pinned down precisely before guest entry
/// depends on this path.
const VM_FLAGS_OVERWRITE: libc::c_int = 0x4000;

/// `VM_INHERIT_NONE`: the destination mapping [`mach_vm_remap`] creates is not
/// inherited by a child process across `fork`. LiteBox does not implement
/// `fork` today, so this is a documentation-accuracy choice more than a
/// behavioral one, but it is the correct value regardless.
const VM_INHERIT_NONE: libc::c_int = 2;

/// `VM_REGION_BASIC_INFO_64` flavor selector for `mach_vm_region`.
const VM_REGION_BASIC_INFO_64: libc::c_int = 9;

type MachPort = u32;
type KernReturn = libc::c_int;

unsafe extern "C" {
    /// The Mach port naming this task. libSystem exports it as a global; the
    /// familiar `mach_task_self()` is a macro over exactly this symbol.
    static mach_task_self_: MachPort;

    /// # Safety
    ///
    /// `address` must point at a writable `u64` holding the requested address.
    pub(crate) fn mach_vm_allocate(
        target: MachPort,
        address: *mut u64,
        size: u64,
        flags: libc::c_int,
    ) -> KernReturn;

    /// Releases a Mach VM allocation made by [`mach_vm_allocate`]. Used to undo
    /// a `VM_FLAGS_FIXED` reservation when the `mmap` that was meant to replace
    /// it fails, so a failed allocation never permanently reserves address
    /// space.
    pub(crate) fn mach_vm_deallocate(target: MachPort, address: u64, size: u64) -> KernReturn;

    fn mach_vm_read_overwrite(
        target: MachPort,
        address: u64,
        size: u64,
        data: u64,
        out_size: *mut u64,
    ) -> KernReturn;

    /// Moves or aliases an existing mapping to a new address, used here to
    /// relocate a `MAP_JIT` mapping created at a kernel-chosen address (see
    /// [`remap_to_fixed`] for why it cannot simply be `mmap(MAP_FIXED)`'d
    /// there directly). `used_for_jit` is a property of the underlying VM map
    /// entry that this preserves across the move; it is not re-derived from
    /// flags passed here.
    ///
    /// # Safety
    ///
    /// `target_address` must point at a writable `u64` holding the requested
    /// destination address; `cur_protection`/`max_protection` must point at
    /// writable `vm_prot_t` (`c_int`) out-parameters.
    fn mach_vm_remap(
        target_task: MachPort,
        target_address: *mut u64,
        size: u64,
        mask: u64,
        flags: libc::c_int,
        src_task: MachPort,
        src_address: u64,
        copy: libc::c_int,
        cur_protection: *mut libc::c_int,
        max_protection: *mut libc::c_int,
        inheritance: libc::c_int,
    ) -> KernReturn;

    fn mach_vm_region(
        target: MachPort,
        address: *mut u64,
        size: *mut u64,
        flavor: libc::c_int,
        info: *mut libc::c_int,
        info_count: *mut u32,
        object_name: *mut MachPort,
    ) -> KernReturn;

    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;

    /// Toggles this thread's access to `MAP_JIT` mappings between writable and
    /// executable. Available since macOS 11, which predates every Apple Silicon
    /// machine.
    pub(crate) fn pthread_jit_write_protect_np(enabled: libc::c_int);

    /// Instruction-cache invalidation from `libkern/OSCacheControl.h`: makes
    /// writes to `[start, start + len)` visible to instruction fetch,
    /// performing the full AArch64 `dc cvau`/`ic ivau`/barrier sequence (and,
    /// per Apple's header, any chip-specific extra work) on the caller's
    /// behalf. Required after writing code that will be executed; Apple
    /// Silicon does not keep I-cache and D-cache coherent automatically.
    pub(crate) fn sys_icache_invalidate(start: *mut libc::c_void, len: usize);

    fn __ulock_wait2(
        operation: u32,
        addr: *mut libc::c_void,
        value: u64,
        timeout_ns: u64,
        value2: u64,
    ) -> libc::c_int;

    fn __ulock_wake(operation: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

/// The Mach port naming this task.
pub(crate) fn mach_task_self() -> MachPort {
    // SAFETY: reading an immutable global libSystem publishes for this purpose.
    unsafe { mach_task_self_ }
}

pub(crate) fn read_task_u32s<const N: usize>(address: usize) -> Option<[u32; N]> {
    let mut words = [0; N];
    let bytes = u64::try_from(core::mem::size_of_val(&words)).ok()?;
    let mut copied = 0;
    let result = unsafe {
        mach_vm_read_overwrite(
            mach_task_self(),
            address as u64,
            bytes,
            words.as_mut_ptr() as u64,
            &raw mut copied,
        )
    };
    (result == KERN_SUCCESS && copied == bytes).then_some(words)
}

/// The outcome of a failed [`reserve_fixed`] call.
pub(crate) enum ReservationError {
    /// Some part of the range is already mapped.
    AddressInUse,
    /// The reservation could not be made for any other reason.
    OutOfMemory,
}

/// Claims `range` via `mach_vm_allocate(VM_FLAGS_FIXED)`.
///
/// This is Darwin's substitute for Linux's `MAP_FIXED_NOREPLACE`: unlike a
/// plain `mmap(MAP_FIXED)`, it fails with `KERN_NO_SPACE` (reported here as
/// [`ReservationError::AddressInUse`]) if any part of the range is already
/// mapped, rather than silently replacing it. A caller that goes on to `mmap`
/// over the reservation and finds that call itself fails must release the
/// reservation via [`release_reservation`] -- otherwise the range is
/// permanently claimed despite the overall allocation having failed.
pub(crate) fn reserve_fixed(range: &core::ops::Range<usize>) -> Result<(), ReservationError> {
    let mut addr = range.start as u64;
    // SAFETY: `mach_task_self()` names this process, and the caller guarantees
    // `range` is page-aligned (every [`PageManagementProvider`] entry point
    // checks this before reaching here).
    let kr = unsafe {
        mach_vm_allocate(
            mach_task_self(),
            &raw mut addr,
            range.len() as u64,
            VM_FLAGS_FIXED,
        )
    };
    match kr {
        KERN_SUCCESS => Ok(()),
        KERN_NO_SPACE => Err(ReservationError::AddressInUse),
        _ => Err(ReservationError::OutOfMemory),
    }
}

/// Releases a reservation made by [`reserve_fixed`].
///
/// Must be called only when nothing has since been mapped over `range` --
/// deallocating a range that now holds a real mapping would unmap it instead.
pub(crate) fn release_reservation(range: &core::ops::Range<usize>) {
    // SAFETY: the caller guarantees `range` still holds exactly the reservation
    // `reserve_fixed` made and nothing else has mapped over it.
    unsafe { mach_vm_deallocate(mach_task_self(), range.start as u64, range.len() as u64) };
}

/// Relocates the mapping at `src_addr` (of `len` bytes) to `dest`, unmapping
/// whatever was previously at `dest`.
///
/// This places a `MAP_JIT` mapping at a specific address. Darwin's `mmap`
/// refuses to combine `MAP_FIXED` with `MAP_JIT` in one call -- real-world
/// precedent (OpenJDK's fix for JDK-8234930, and V8's `OS::RemapPages` in
/// `src/base/platform/platform-darwin.cc`, both of which use exactly this
/// create-then-remap sequence on macOS/Apple Silicon) creates the JIT mapping
/// at a kernel-chosen address first, then uses `mach_vm_remap` to move it. The
/// destination mapping keeps the source's JIT-capable property: it lives on
/// the underlying `vm_map_entry` (an internal `used_for_jit` bit), which
/// `mach_vm_remap`'s entry-copy path preserves.
///
/// `copy = TRUE` (not the aliasing `FALSE`): measured on real hardware,
/// `mach_vm_remap(copy=FALSE)` returns `KERN_PROTECTION_FAILURE` for *every*
/// `MAP_JIT` source -- live-confirmed here as the exact reason a `MAP_JIT`
/// mapping could never be placed at a fixed address, which is what blocked
/// V8's code-range promotion. `copy=TRUE` is a copy-on-write entry duplication
/// (lazy: no physical copy of untouched pages), yields a genuinely executable
/// JIT destination (verified by writing `movz w0,#42; ret` into a source and
/// executing it from the remapped destination), and lets the caller drop its
/// now-redundant source mapping afterward -- the destination is an independent
/// COW copy, not an alias, so the source `munmap` does not disturb it.
///
/// # Safety
///
/// `src_addr` must be the base of a live mapping of exactly `len` bytes that
/// the caller owns and is not otherwise using concurrently.
pub(crate) unsafe fn remap_to_fixed(
    src_addr: usize,
    len: usize,
    dest: usize,
) -> Result<(), ReservationError> {
    let mut target = dest as u64;
    let mut cur_protection: libc::c_int = 0;
    let mut max_protection: libc::c_int = 0;
    // SAFETY: `mach_task_self()` names this process for both the source and
    // destination (an intra-process move); `target`/`cur_protection`/
    // `max_protection` are live local out-parameters; `src_addr`/`len` are the
    // caller's obligation per this function's own safety doc.
    let kr = unsafe {
        mach_vm_remap(
            mach_task_self(),
            &raw mut target,
            len as u64,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            mach_task_self(),
            src_addr as u64,
            1, // copy = TRUE: COW-duplicate; required for MAP_JIT sources.
            &raw mut cur_protection,
            &raw mut max_protection,
            VM_INHERIT_NONE,
        )
    };
    match kr {
        KERN_SUCCESS => Ok(()),
        KERN_NO_SPACE => Err(ReservationError::AddressInUse),
        _ => Err(ReservationError::OutOfMemory),
    }
}

/// Walk every mapped region of this process, yielding its address range.
///
/// This is the Mach counterpart of Windows' `VirtualQuery` loop: it reports what
/// the host already occupies so those addresses are never offered to a guest.
pub(crate) fn mach_vm_region_iter() -> impl Iterator<Item = core::ops::Range<usize>> {
    let mut address: u64 = 0;
    core::iter::from_fn(move || {
        loop {
            let mut size: u64 = 0;
            // `vm_region_basic_info_data_64_t` is a plain struct of `int`-sized
            // fields plus one 64-bit offset; the count is in units of `int`.
            let mut info = [0i32; 16];
            let mut info_count = u32::try_from(info.len()).expect("fixed small length");
            let mut object_name: MachPort = 0;
            // SAFETY: every out-parameter points at a live local of the right
            // type, and `info_count` bounds the writes into `info`.
            let kr = unsafe {
                mach_vm_region(
                    mach_task_self(),
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    info.as_mut_ptr(),
                    &raw mut info_count,
                    &raw mut object_name,
                )
            };
            if kr != KERN_SUCCESS {
                return None;
            }
            if object_name != 0 {
                // `mach_vm_region` hands back a send right that would otherwise
                // leak a port for every region walked.
                //
                // SAFETY: the port was just produced by the call above.
                unsafe { mach_port_deallocate(mach_task_self(), object_name) };
            }
            let start = usize::try_from(address).ok()?;
            let len = usize::try_from(size).ok()?;
            // Advance past this region before yielding, so the next call
            // resumes after it.
            address = address.checked_add(size)?;
            if len == 0 {
                // A zero-length region would not advance the walk; skip it
                // rather than spin.
                continue;
            }
            return Some(start..start + len);
        }
    })
}

// `ulock` operation codes and flags, from xnu's `sys/ulock.h`.
//
// Raw mutexes live in process-private Rust storage, so the private operation's
// `(task, address)` key is the correct domain. The shared operation instead keys
// through VM-object identity and is intended for interprocess mappings.
const UL_COMPARE_AND_WAIT: u32 = 1;
const ULF_WAKE_ALL: u32 = 0x0000_0100;
/// Return `-errno` directly instead of setting `errno`, which keeps these calls
/// free of thread-local access on the wait path.
const ULF_NO_ERRNO: u32 = 0x0100_0000;

/// Outcome of a [`ulock_wait`].
pub(crate) enum UlockWaitResult {
    /// The thread slept and was woken (possibly spuriously).
    Woken,
    /// The deadline passed without a wake.
    TimedOut,
    /// The value had already changed, so the thread never slept.
    ValueChanged,
}

/// Sleep while `*atomic == value`, in the manner of `FUTEX_WAIT`.
///
/// A `None` timeout waits indefinitely.
pub(crate) fn ulock_wait(
    atomic: &AtomicU32,
    value: u32,
    timeout: Option<Duration>,
) -> UlockWaitResult {
    // XNU reports an immediate compare mismatch with the same nonnegative return
    // value as a real wake. A userspace precheck preserves the trait's distinct
    // immediate-mismatch result when the value has already changed; a change
    // racing after this load remains a permitted spurious wake.
    if atomic.load(Ordering::Relaxed) != value {
        return UlockWaitResult::ValueChanged;
    }

    // `__ulock_wait2` takes nanoseconds, with zero meaning "no deadline". A
    // non-zero requested duration must therefore never round down to zero, or
    // a timed wait would silently become an infinite one.
    let timeout_ns = match timeout {
        None => 0,
        Some(duration) => u64::try_from(duration.as_nanos())
            .unwrap_or(u64::MAX)
            .max(1),
    };
    let addr = core::ptr::from_ref(atomic)
        .cast_mut()
        .cast::<libc::c_void>();
    // SAFETY: `addr` points at a live `AtomicU32`, which is what the
    // compare-and-wait operation reads.
    let rc = unsafe {
        __ulock_wait2(
            UL_COMPARE_AND_WAIT | ULF_NO_ERRNO,
            addr,
            u64::from(value),
            timeout_ns,
            0,
        )
    };
    if rc >= 0 {
        // The return value counts the waiters still parked; any of them is a
        // successful sleep-and-wake for this thread.
        return UlockWaitResult::Woken;
    }
    match -rc {
        // A signal cut the wait short. The caller must tolerate spurious
        // wakeups anyway, so this is indistinguishable from a real one.
        libc::EINTR => UlockWaitResult::Woken,
        libc::ETIMEDOUT => UlockWaitResult::TimedOut,
        errno => panic!("__ulock_wait2 failed with errno {errno}"),
    }
}

/// Wake one or all threads parked on `atomic`, in the manner of `FUTEX_WAKE`.
pub(crate) fn ulock_wake(atomic: &AtomicU32, all: bool) {
    let mut operation = UL_COMPARE_AND_WAIT | ULF_NO_ERRNO;
    if all {
        operation |= ULF_WAKE_ALL;
    }
    let addr = core::ptr::from_ref(atomic)
        .cast_mut()
        .cast::<libc::c_void>();
    // SAFETY: `addr` points at a live `AtomicU32`.
    let rc = unsafe { __ulock_wake(operation, addr, 0) };
    assert!(
        rc == 0 || rc == -libc::ENOENT,
        "__ulock_wake failed with errno {}",
        -rc
    );
}

/// Read a clock as whole nanoseconds.
pub(crate) fn clock_gettime_nanos(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a live, correctly typed out-parameter.
    let rc = unsafe { libc::clock_gettime(clock, &raw mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed for clock {clock}");
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nsecs = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000_000_000).saturating_add(nsecs)
}

/// Read a string-valued `sysctl` by name.
/// Reads an integer `sysctl` (e.g. `hw.cachelinesize`) as a `u64`, widening
/// whatever width the kernel returns (`u32`/`u64`). Returns `None` if the
/// name does not exist or is wider than 8 bytes.
pub(crate) fn sysctl_u64(name: &core::ffi::CStr) -> Option<u64> {
    let mut buf = [0u8; 8];
    let mut len: usize = buf.len();
    // SAFETY: `buf`/`len` are valid, uniquely-owned out-parameters sized for
    // the widest integer sysctl this reads.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || len == 0 || len > 8 {
        return None;
    }
    let mut v = [0u8; 8];
    v[..len].copy_from_slice(&buf[..len]);
    Some(u64::from_le_bytes(v))
}

pub(crate) fn sysctl_string(
    name: &core::ffi::CStr,
) -> Result<alloc::string::String, std::io::Error> {
    let mut len: usize = 0;
    // SAFETY: passing a null buffer asks only for the required length.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            core::ptr::null_mut(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = alloc::vec![0u8; len];
    // SAFETY: `buf` has exactly the length the call above asked for.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &raw mut len,
            core::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The value is NUL-terminated and `len` counts the terminator.
    buf.truncate(len.saturating_sub(1));
    alloc::string::String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "sysctl value not UTF-8"))
}

/// Install `handler` for `signum`.
///
/// `siginfo` selects the three-argument handler form, which is what a fault
/// handler needs in order to reach the interrupted machine context.
///
/// Always `SA_ONSTACK`: every signal installed through this function is one
/// that can land while a guest is executing (see
/// `litebox_platform_macos_userland::guest`'s below-`SP` staging note), and
/// `SA_ONSTACK` falls back to the current stack on a thread that never
/// registered an alternate one, so this is never a regression for a handler
/// that turns out not to need it.
///
/// `extra_mask` names signals to block for the duration of this handler,
/// beyond `signum` itself (which the kernel already blocks by default absent
/// `SA_NODEFER`). This matters whenever two handlers installed through this
/// function touch the same thread's guest-entry state
/// (`litebox_platform_macos_userland::guest`'s `GuestThreadState`: its
/// `owns_cpu`, `live_ptregs`, `guest_fp`, `pending_exception_info` and
/// `pending_interrupt` fields). Unlike `SIGSEGV`/`SIGBUS`/`SIGUSR2` being
/// merely reentrant-safe Rust code in isolation, none of those fields is
/// protected against a *second* handler invocation nesting on top of a first
/// one still in flight on the same thread. Per-thread storage is exactly what
/// does *not* help here: it rules out a *different* guest thread racing this
/// one, which was never the hazard, and says nothing about this same thread's
/// own signal handler being interrupted by a different signal. The fault
/// handler and the interrupt handler are exactly this pair -- a real guest
/// hardware fault and an unrelated cross-thread `ThreadHandle::interrupt`
/// call can race, and without masking, the second signal would nest atop the
/// first mid-update.
///
/// # Panics
///
/// Panics if the handler cannot be installed, which would leave LiteBox unable
/// to recover from a faulting guest-memory access.
pub(crate) fn install_handler(
    signum: libc::c_int,
    handler: usize,
    siginfo: bool,
    extra_mask: &[libc::c_int],
) {
    // SAFETY: `sigaction` is a plain-old-data struct; zero is a valid initial
    // value for every field, and the fields that matter are set below.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = (if siginfo { libc::SA_SIGINFO } else { 0 }) | libc::SA_ONSTACK;
    // SAFETY: `sa_mask` is a live, correctly typed out-parameter, and installing
    // a handler for a signal number the caller chose has no other precondition.
    let rc = unsafe {
        libc::sigemptyset(&raw mut action.sa_mask);
        for &extra in extra_mask {
            libc::sigaddset(&raw mut action.sa_mask, extra);
        }
        libc::sigaction(signum, &raw const action, core::ptr::null_mut())
    };
    assert_eq!(rc, 0, "failed to install a handler for signal {signum}");
}

/// Restore the default disposition of `signum` so that returning from a
/// synchronous fault handler lets the fault kill the process, exactly as it
/// would have without a handler installed.
pub(crate) fn reraise_fatally(signum: libc::c_int) {
    // SAFETY: as in `install_handler`.
    unsafe {
        let mut action: libc::sigaction = core::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&raw mut action.sa_mask);
        libc::sigaction(signum, &raw const action, core::ptr::null_mut());
    }
}

/// Darwin's `_STRUCT_MCONTEXT64` for arm64: exception state, thread state, then
/// NEON state, with no padding between them -- verified directly against
/// `arm/_mcontext.h` and `mach/arm/_structs.h` in this machine's real SDK
/// (`xcrun --show-sdk-path`), not assumed. `exception_state` is 16 bytes and
/// `thread_state` is 272 bytes, so `neon_state` (which needs 16-byte alignment
/// for its `__uint128_t` array) already lands on a 16-byte boundary (288 is a
/// multiple of 16) without an explicit padding field.
#[repr(C)]
// The shared `_state` postfix mirrors the real struct's own field names
// (`__es`/`__ss`/`__ns` all name Mach "thread state" flavors); renaming would
// make this struct harder to cross-check against the SDK header, not easier.
#[allow(clippy::struct_field_names)]
pub(crate) struct McontextPrefix64 {
    pub(crate) exception_state: ArmExceptionState64,
    pub(crate) thread_state: ArmThreadState64,
    pub(crate) neon_state: ArmNeonState64,
}

/// Darwin's `_STRUCT_ARM_EXCEPTION_STATE64`.
#[repr(C)]
pub(crate) struct ArmExceptionState64 {
    /// Faulting virtual address (`FAR_EL1`).
    pub(crate) far: u64,
    /// Exception syndrome (`ESR_EL1`).
    pub(crate) esr: u32,
    /// The Mach exception number the fault was reported as.
    pub(crate) exception: u32,
}

/// Darwin's `_STRUCT_ARM_THREAD_STATE64`.
#[repr(C)]
pub(crate) struct ArmThreadState64 {
    /// General-purpose registers `x0`-`x28`.
    pub(crate) x: [u64; 29],
    /// Frame pointer, `x29`.
    pub(crate) fp: u64,
    /// Link register, `x30`.
    pub(crate) lr: u64,
    pub(crate) sp: u64,
    pub(crate) pc: u64,
    pub(crate) cpsr: u32,
    /// Inert padding for the userspace, non-ptrauth ABI this crate targets
    /// (built without `ptrauth_calls`, the only configuration a plain
    /// `aarch64-apple-darwin` Rust toolchain produces). XNU's own header
    /// documents this same offset differently under two other configurations
    /// this crate does not use: as a real `flags` field with pointer-
    /// authentication metadata (`NO_PTRAUTH`/`IB_SIGNED_LR`/etc.) in the
    /// kernel-internal variant, and as opaque signed-pointer fields in place
    /// of plain `pc`/`lr` under the arm64e ABI. If this platform ever needs
    /// arm64e/PAC support, this field's meaning must be revisited alongside
    /// `pc`/`lr`, not read as inert padding.
    pub(crate) pad: u32,
}

/// Darwin's `_STRUCT_ARM_NEON_STATE64`: `v: [__uint128_t; 32]`, then `fpsr`,
/// then `fpcr` (in that order -- verified against `mach/arm/_structs.h` in
/// this machine's real SDK; note the aarch64 Linux ABI's own `fpsimd_context`
/// puts `fpsr`/`fpcr` *before* its vector array instead, so the two are not
/// byte-for-byte interchangeable despite being the same overall size).
#[repr(C)]
pub(crate) struct ArmNeonState64 {
    /// `v0`-`v31`, full 128 bits each.
    pub(crate) v: [u128; 32],
    pub(crate) fpsr: u32,
    pub(crate) fpcr: u32,
}

const _: () = assert!(core::mem::size_of::<ArmExceptionState64>() == 16);
const _: () = assert!(core::mem::size_of::<ArmThreadState64>() == 272);
const _: () = assert!(core::mem::offset_of!(McontextPrefix64, exception_state) == 0);
const _: () = assert!(core::mem::offset_of!(McontextPrefix64, thread_state) == 16);
const _: () = assert!(core::mem::offset_of!(McontextPrefix64, neon_state) == 288);
const _: () = assert!(core::mem::offset_of!(ArmNeonState64, v) == 0);
const _: () = assert!(core::mem::offset_of!(ArmNeonState64, fpsr) == 512);
const _: () = assert!(core::mem::offset_of!(ArmNeonState64, fpcr) == 516);
// 520 logical bytes (512 + 4 + 4), but `#[repr(C)]` rounds the overall size up
// to a multiple of the struct's own 16-byte alignment (forced by the
// `__uint128_t` array) -- 8 bytes of trailing padding, exactly matching the
// real Darwin struct's own C layout, not a Rust-specific quirk.
const _: () = assert!(core::mem::size_of::<ArmNeonState64>() == 528);
