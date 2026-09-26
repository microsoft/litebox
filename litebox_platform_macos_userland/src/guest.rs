// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest entry for Darwin on aarch64.
//!
//! This is the transfer of control *into* guest code and back out of it -- the
//! counterpart of the other platforms' `run_thread_arch`. Everything else of
//! the macOS platform (memory, locking, time, signals, threads, TLS,
//! randomness, stdio, networking) was already complete; this module closes the
//! last seam so a guest thread can actually execute.
//!
//! # The context-switch mechanism
//!
//! AArch64 has no userland instruction that atomically restores every general
//! register *and* the program counter (that is `ERET`, EL1+ only). Every
//! indirect branch (`BR`/`RET`) reads a general register, so entering the guest
//! must sacrifice exactly one register as the branch vehicle. [`enter_guest_asm`]
//! restores all of `X0`-`X30`, `SP` and the `NZCV` flags from a [`PtRegs`], then
//! branches through **`X17`** to the guest `PC`.
//!
//! `X17`, not `X16`, is the vehicle. An earlier revision sacrificed `X16`
//! (reasoning that the [`litebox_syscall_rewriter`] `SVC` gate already treats
//! it as scratch, and that the Linux syscall ABI does not keep a live value in
//! `X16`/`X17` across an `SVC` in practice) -- but that discarded the guest's
//! real `X16` on *every* resume, not only across a syscall, which is a real
//! ABI divergence: the kernel's own guarantee is that a raw `SVC` preserves
//! every register but `X0`, and this platform's own resume path was the one
//! exception to it. Measured directly against a real `node:alpine` guest,
//! this was not merely theoretical: a genuine, reproducible late-boot crash
//! (guest `PC` and `X16` landing on identical, non-deterministic garbage --
//! `0`, or raw bytes read out of a nearby path string -- after `BLR`-through-
//! `X16`-shaped guest code) persisted **identically** whether `X16` or `X17`
//! served as the sacrificed vehicle, which is the decisive evidence: the
//! guest's own code holds `X16` live and something *other* than this
//! platform's vehicle choice is corrupting it (see `docs/roadmap.md`'s
//! "XNU destroys a live guest `x18`" section for the same failure *class*,
//! confirmed there for a different register, on this same host). Restoring
//! `X16` correctly does not fix that crash, but it closes a confirmed, live
//! ABI gap independent of it, at zero measured cost (the existing round-trip
//! tests below, and a full `node:alpine` re-run, show no regression).
//!
//! The vector registers travel separately, in [`GuestThreadState::guest_fp`],
//! because [`PtRegs`] has nowhere to put them: it mirrors Linux's `struct
//! pt_regs`, which carries no FP state because the kernel is built without it.
//! Leaving them in the hardware would not work either -- the shim is ordinary
//! Rust and uses vector registers freely -- and Linux preserves user FPSIMD
//! across a syscall, so a guest may hold live values in any of them across its
//! `SVC`.
//!
//! Coming back is the reverse. A rewritten guest `SVC` branches (via its gate
//! and the shared handler) to this module's syscall entry point, which captures
//! the full guest register file into the run loop's `PtRegs`, restores the
//! host's callee-saved registers and stack, and returns *normally* into the run
//! loop -- a hand-rolled `swapcontext`. The run loop ([`run_thread`]) then calls
//! the shim and, on [`ContinueOperation::Resume`], re-enters with the updated
//! `PtRegs`. This avoids `setjmp`/`longjmp` (unsound across Rust frames) and
//! the deprecated `ucontext` API (whose `setcontext` resumes via `__lr`, which
//! would clobber the guest's live `X30` -- worse than clobbering `X16`).
//!
//! # Per-thread bookkeeping: the one-register `TPIDRRO_EL0` reach
//!
//! Everything the switch has to remember across a guest's syscall -- the host
//! save area, the live-[`PtRegs`] pointer, the guest's vector file, the
//! "guest owns the CPU" flag and the pending-interrupt flag -- lives in a
//! single per-thread [`GuestThreadState`], so this platform runs **as many
//! concurrent guest threads as the host will give it**. Reaching it is the
//! whole difficulty, and it is worth spelling out why the obvious answers do
//! not work:
//!
//! * A Rust `thread_local!` needs a function call, and
//!   [`syscall_entry_stubs`]'s callback body runs on the *guest's* stack with
//!   every guest register live -- there is nothing to call with and nowhere to
//!   spill to.
//! * `litebox_platform_linux_userland`'s x86_64 switch reads its equivalent
//!   state from `fs:`-relative local-exec TLS, a link-time-fixed offset with no
//!   call. Mach-O has no equivalent addressing mode.
//! * Darwin *does* expose exactly the right primitive: a `pthread_key_create`
//!   key `N`'s value sits at `[(TPIDRRO_EL0 & !7) + N*8]`, the same "direct
//!   TSD" read libSystem's own `errno` accessor uses. But `N` is only known at
//!   run time (this process's first dynamic key is not a fixed number -- see
//!   `lib.rs`'s `reserve_guest_tpidr_tsd_slot`), and materialising a run-time
//!   offset costs a *second* scratch register. At the syscall callback, the
//!   rewriter's `SVC` gate has left exactly **one** register free (`X16`);
//!   `X17` still holds the guest's real value.
//! * Staging the pointer below the guest `SP` at resume time buys the second
//!   register, and is **wrong**: the guest's own `SP` moves between a resume
//!   and its next syscall (any compiled function that opens a stack frame does
//!   this), so the staged word is at a stale address. That design was built,
//!   tested and hardware-disproven; see `docs/roadmap.md`.
//!
//! What this module does instead is make the offset a *compile-time* constant
//! by enumerating every possible one. [`syscall_entry_stubs`] is a table of
//! [`TSD_SLOT_COUNT`] identical four-instruction stubs, stub `N` being
//!
//! ```text
//! mrs x16, tpidrro_el0
//! and x16, x16, #~7
//! ldr x16, [x16, #(N * 8)]     // N is an assemble-time immediate
//! b   <callback body>
//! ```
//!
//! and [`syscall_entry_point`] hands the guest's loader the address of the one
//! stub matching the key this process actually reserved. One register, no call,
//! no guest-`SP` dependence, no self-modifying code, and no change to the
//! ahead-of-time-rewritten guest binary format: the guest is already told the
//! entry point at load time (`SystemInfoProvider::get_syscall_entry_point`), so
//! choosing *which* stub is free. The table costs `TSD_SLOT_COUNT * 16` bytes
//! of `.text` and is otherwise inert.
//!
//! The other five naked functions here are reached with registers to spare
//! (three of them by a signal handler's `pc` redirect, so *every* register is
//! free), and simply do the two-register lookup -- `MRS` plus a load of
//! [`GUEST_STATE_TSD_BYTE_OFFSET`] -- inline.
//!
//! # Current limitations
//!
//! * **Guest hardware faults (`SIGSEGV`/`SIGBUS`) are routed** to
//!   [`litebox::shim::EnterShim::exception`] via
//!   [`GuestThreadState::owns_cpu`] and `lib.rs`'s `fault_handler`. A delivered
//!   exception's captured general registers/`PSTATE`/vector state are all
//!   exact, read straight from the kernel's own signal `mcontext` (see
//!   [`prepare_exception_delivery`]).
//! * **The interrupt path (`SIGUSR2`) is routed** to
//!   [`litebox::shim::EnterShim::interrupt`] via `lib.rs`'s
//!   `interrupt_signal_handler`, [`interrupted_pc_is_in_guest_entry_restore`]/
//!   [`interrupted_pc_is_in_guest_exit_prologue`],
//!   [`GuestThreadState::pending_interrupt`] and
//!   [`prepare_interrupt_delivery`]/[`abandon_guest_entry_for_interrupt`] --
//!   see those items' own doc comments for the four-case dispatch this needed
//!   (mirroring `litebox_platform_linux_userland`'s and
//!   `litebox_platform_windows_userland`'s own four-case interrupt handling).
//! * **Guest-`SP` independence at entry.** [`enter_guest_asm`] never reads or
//!   writes guest memory. It keeps the host-owned [`PtRegs`] pointer in `X0`
//!   until its final two loads, putting the guest `PC` into the deliberately
//!   sacrificed `X17` branch vehicle and the guest `X0` into `X0` itself. A
//!   corrupt or concurrently-unmapped guest `SP` therefore becomes an ordinary
//!   guest fault only when guest code actually uses it; it cannot fault inside
//!   the host context switch. Guest-directed signals still run on a
//!   `sigaltstack`, because the interrupted guest `SP` itself may be precisely
//!   what faulted and is never a valid host signal-handler stack assumption.
//!
//! Darwin's W^X rules still apply: the guest's executable pages are `MAP_JIT`
//! mappings and every patch is bracketed by
//! [`litebox::platform::PageManagementProvider::jit_write_protect`] (the shim's
//! code-writing paths already do this), with the host binary signed for the
//! `com.apple.security.cs.allow-jit` entitlement.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use litebox::shim::ContinueOperation;
use litebox::utils::TruncateExt as _;
use litebox_common_linux::PtRegs;

// The naked assembly below hard-codes byte offsets into `PtRegs` and its total
// size. These assertions tie those literals to the struct definition so a
// layout change fails the build instead of silently miscompiling the switch.
const _: () = assert!(core::mem::offset_of!(PtRegs, regs) == 0);
const _: () = assert!(core::mem::offset_of!(PtRegs, sp) == 248);
const _: () = assert!(core::mem::offset_of!(PtRegs, pc) == 256);
const _: () = assert!(core::mem::offset_of!(PtRegs, pstate) == 264);
const _: () = assert!(core::mem::offset_of!(PtRegs, orig_x0) == 272);
const _: () = assert!(core::mem::offset_of!(PtRegs, syscallno) == 280);
const _: () = assert!(core::mem::size_of::<PtRegs>() == 288);

/// The guest's floating-point and SIMD state, held across a syscall.
///
/// The guest's own registers cannot stay in the hardware while the host runs:
/// the shim is ordinary Rust and uses the vector registers freely, so anything
/// left live would be destroyed. [`PtRegs`] cannot carry this state -- it mirrors
/// Linux's `struct pt_regs`, which has no FP fields because the kernel is built
/// without them and manages user FPSIMD out of band -- so it lives beside it.
///
/// The whole file is preserved, not just the callee-saved half, because Linux
/// preserves user FPSIMD across a syscall: a guest is entitled to hold live
/// values in *any* vector register across its `SVC`, and glibc's and musl's
/// string and memory routines do exactly that.
#[repr(C, align(16))]
struct GuestFpState {
    /// `v0`-`v31`, full 128 bits each.
    v: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

/// Everything one guest thread's context switch has to remember while the host
/// runs, reached from naked assembly by a `TPIDRRO_EL0`-relative direct-TSD
/// read (see this module's own doc comment for why that specific mechanism).
///
/// One of these lives on each guest thread's own host stack for exactly as long
/// as [`run_thread`] is running there, and a pointer to it is published in the
/// pthread TSD slot [`GUEST_STATE_TSD_BYTE_OFFSET`] names. Nothing here is
/// shared between threads, so nothing here needs cross-thread synchronisation
/// -- but [`Self::owns_cpu`] and [`Self::pending_interrupt`] are still atomics,
/// because a *signal handler on this same thread* reads and writes them
/// asynchronously with respect to the mainline code, which a plain field would
/// let the compiler cache or reorder across.
///
/// The byte offsets are hard-coded in six naked `asm!` blocks; the assertions
/// below pin them to this definition so a layout change fails the build instead
/// of silently miscompiling the switch.
#[repr(C, align(16))]
pub(crate) struct GuestThreadState {
    /// Host callee-saved state, saved by [`enter_guest_asm`] and restored by
    /// the syscall/exception/interrupt callbacks. Byte layout, relative to
    /// this field: `x19..x28` at 0..72, `x29` at 80, `lr` at 88, `sp` at 96,
    /// `d8..d15` at 104..160, `FPCR` at 168, `FPSR` at 176.
    ///
    /// `d8`-`d15` are here because AAPCS makes their low 64 bits callee-saved,
    /// so `run_thread`'s caller is entitled to find them intact; the guest is
    /// free to write every vector register.
    host_save: [u64; HOST_SAVE_SLOTS],
    /// Pads [`Self::guest_fp`] out to its own 16-byte alignment. Explicit
    /// rather than implicit so the offset assertions below read as a layout
    /// specification rather than a restatement of the compiler's choice.
    _align_pad: u64,
    /// The live guest's FP/SIMD state while the host runs. Restored by
    /// [`enter_guest_asm`], captured by the syscall callback. Zero is the
    /// correct initial value: a fresh guest thread starts with a cleared vector
    /// file and the default rounding mode, which is what `FPCR == 0` means.
    guest_fp: GuestFpState,
    /// Pointer to the run loop's live [`PtRegs`], stashed by
    /// [`enter_guest_asm`] so the syscall callback can write the captured guest
    /// state back into it.
    live_ptregs: *mut PtRegs,
    /// Whether the CPU is genuinely executing guest instructions right now, as
    /// opposed to running this platform's own [`enter_guest_asm`]/syscall-
    /// callback switch code with the guest's registers not yet (or no longer)
    /// authoritative. `lib.rs`'s `fault_handler` consults this -- *after* its
    /// existing exception-table check, which always takes priority -- to decide
    /// whether a captured `mcontext` is safe to hand to the guest via
    /// [`litebox::shim::EnterShim::exception`], or must instead be left alone
    /// as an internal/unattributable fault (today's behavior: the process
    /// dies).
    ///
    /// Set `true` by [`enter_guest_asm`] once every guest register but the
    /// branch vehicle is ready to be restored, and cleared `false` as the first
    /// memory write of the syscall callback body and of
    /// [`sigreturn_trampoline`], and by `fault_handler` itself when it delivers
    /// an exception. Guest entry itself touches only the host-owned `PtRegs` and
    /// per-thread state, never the guest stack. The syscall callback still reads
    /// the two words the rewritten `SVC` gate stashed at the guest `SP`; that
    /// narrow exit window is covered by an exception-table entry recovering to
    /// [`abort_on_boundary_stack_fault`], which the exception-table check
    /// `fault_handler` runs first always finds before this flag is consulted.
    owns_cpu: AtomicBool,
    /// Set by `lib.rs`'s `interrupt_signal_handler` whenever a `SIGUSR2`
    /// arrives at a moment it cannot redirect immediately (this thread was not
    /// genuinely executing guest code -- [`Self::owns_cpu`] false, or `SIGUSR2`
    /// landed inside the syscall callback's/[`sigreturn_trampoline`]'s own
    /// brief ownership-clearing prologue), so the delivery is not simply lost.
    /// Checked and cleared by [`enter_guest_asm`] immediately after it sets
    /// [`Self::owns_cpu`] true for a fresh entry, *before* restoring any guest
    /// register -- mirroring `litebox_platform_linux_userland::switch_to_guest`'s
    /// own `cmp .../jne interrupt_callback` placed immediately after its
    /// `in_guest := 1` store, for the identical reason: without this re-check,
    /// an interrupt that races the narrow window between the shim deciding a
    /// thread is "running in guest" (and so signalling it) and this platform's
    /// own `owns_cpu` actually becoming true for *that* entry would be silently
    /// dropped until the guest's next syscall -- arbitrarily far away for a
    /// compute-bound guest, defeating the entire point of interrupting one.
    pending_interrupt: AtomicBool,
    /// Pads the two flags out to the pointer-sized tail below. No naked code
    /// addresses this.
    _flag_pad: [u8; 6],
    /// The [`litebox::shim::ExceptionInfo`] for the fault [`exception_callback`]
    /// is about to report to the run loop, filled in by
    /// [`prepare_exception_delivery`] before `lib.rs`'s `fault_handler`
    /// redirects there. Touched only from ordinary Rust, never from naked
    /// assembly, so it needs no pinned offset.
    pending_exception_info: litebox::shim::ExceptionInfo,
}

/// `u64` slots in [`GuestThreadState::host_save`]; see its layout.
const HOST_SAVE_SLOTS: usize = 23;
/// Byte offsets the naked assembly hard-codes. `host_save` is a flat array
/// rather than a struct, so there is no `offset_of!` to check these against;
/// the assertions below check instead that the regions are contiguous and that
/// the last one ends exactly at the end of the array, which is what would break
/// if a slot were added without resizing it.
const HOST_SAVE_OFF_D8: usize = 104;
const HOST_SAVE_OFF_FPCR: usize = 168;
const HOST_SAVE_OFF_FPSR: usize = 176;
/// `d8`-`d15`, eight 64-bit slots, run from `HOST_SAVE_OFF_D8` up to `FPCR`.
const _: () = assert!(HOST_SAVE_OFF_D8 + 8 * 8 == HOST_SAVE_OFF_FPCR);
const _: () = assert!(HOST_SAVE_OFF_FPCR + 8 == HOST_SAVE_OFF_FPSR);
const _: () = assert!(HOST_SAVE_OFF_FPSR + 8 == HOST_SAVE_SLOTS * 8);

/// Byte offset of [`GuestThreadState::host_save`]; zero, so every `host_save`
/// offset above doubles as an offset from the state pointer itself.
const TS_OFF_HOST_SAVE: usize = 0;
/// Byte offset of [`GuestThreadState::guest_fp`].
const TS_OFF_GUEST_FP: usize = 192;
/// Byte offset of [`GuestThreadState::live_ptregs`].
const TS_OFF_LIVE_PTREGS: usize = 720;
/// Byte offset of [`GuestThreadState::owns_cpu`].
const TS_OFF_OWNS_CPU: usize = 728;
/// Byte offset of [`GuestThreadState::pending_interrupt`].
const TS_OFF_PENDING_INTERRUPT: usize = 729;

const _: () = assert!(core::mem::offset_of!(GuestThreadState, host_save) == TS_OFF_HOST_SAVE);
const _: () = assert!(core::mem::offset_of!(GuestThreadState, guest_fp) == TS_OFF_GUEST_FP);
const _: () = assert!(core::mem::offset_of!(GuestThreadState, live_ptregs) == TS_OFF_LIVE_PTREGS);
const _: () = assert!(core::mem::offset_of!(GuestThreadState, owns_cpu) == TS_OFF_OWNS_CPU);
const _: () =
    assert!(core::mem::offset_of!(GuestThreadState, pending_interrupt) == TS_OFF_PENDING_INTERRUPT);

/// Byte offsets *within* [`GuestThreadState::guest_fp`], plus the whole-state
/// offsets the assembly actually uses for the FP control/status words.
const GUEST_FP_OFF_FPCR: usize = 512;
const GUEST_FP_OFF_FPSR: usize = 520;
const _: () = assert!(core::mem::offset_of!(GuestFpState, v) == 0);
const _: () = assert!(core::mem::offset_of!(GuestFpState, fpcr) == GUEST_FP_OFF_FPCR);
const _: () = assert!(core::mem::offset_of!(GuestFpState, fpsr) == GUEST_FP_OFF_FPSR);
/// `TS_OFF_GUEST_FP + GUEST_FP_OFF_FPCR`, spelled out because the assembly
/// needs the literal.
const TS_OFF_GUEST_FPCR: usize = 704;
/// `TS_OFF_GUEST_FP + GUEST_FP_OFF_FPSR`.
const TS_OFF_GUEST_FPSR: usize = 712;
const _: () = assert!(TS_OFF_GUEST_FP + GUEST_FP_OFF_FPCR == TS_OFF_GUEST_FPCR);
const _: () = assert!(TS_OFF_GUEST_FP + GUEST_FP_OFF_FPSR == TS_OFF_GUEST_FPSR);
/// The 128-bit `LDP`/`STP` the vector save/restore uses has a signed 7-bit
/// immediate scaled by 16, i.e. `-1024..=1008`. The last pair (`q30`/`q31`)
/// sits at `TS_OFF_GUEST_FP + 480`, so this must stay in range or the assembly
/// silently fails to assemble.
const _: () = assert!(TS_OFF_GUEST_FP + 480 <= 1008);

impl GuestThreadState {
    /// A freshly-zeroed state for one guest thread. Zero is the correct start
    /// for every field: no host state saved yet, a cleared vector file with the
    /// default rounding mode, no live `PtRegs`, not owning the CPU, no pending
    /// interrupt.
    const fn new() -> Self {
        Self {
            host_save: [0; HOST_SAVE_SLOTS],
            _align_pad: 0,
            guest_fp: GuestFpState {
                v: [0; 32],
                fpcr: 0,
                fpsr: 0,
            },
            live_ptregs: core::ptr::null_mut(),
            owns_cpu: AtomicBool::new(false),
            pending_interrupt: AtomicBool::new(false),
            _flag_pad: [0; 6],
            pending_exception_info: litebox::shim::ExceptionInfo {
                exception: litebox::shim::Exception(0),
                fault_address: 0,
                esr: 0,
                kernel_mode: false,
            },
        }
    }
}

/// How many pthread TSD slots [`syscall_entry_stubs`] emits a stub for.
///
/// Darwin's dynamic `pthread_key_create` range is bounded and small: measured
/// on this hardware (Apple M3 Pro, macOS 26.3.1) the first dynamic key a Rust
/// binary gets is 259 and the pool is exhausted at key 767, matching
/// apple-oss-distributions/libpthread's `_INTERNAL_POSIX_THREAD_KEYS_END`/
/// `_EXTERNAL_POSIX_THREAD_KEYS_MAX` split. 768 stubs therefore cover every key
/// the system can hand out; [`syscall_entry_point`] asserts rather than
/// silently indexing past the table if that ever stops being true.
///
/// The cost is `768 * 16` = 12 KiB of otherwise-inert `.text`.
const TSD_SLOT_COUNT: usize = 768;

/// Bytes per stub in [`syscall_entry_stubs`]: four fixed-width A64
/// instructions.
const TSD_STUB_BYTES: usize = 16;

/// The byte offset (`key * 8`) of this process's per-thread-state pthread TSD
/// slot, or `0` before [`reserve_guest_state_tsd_slot`] has run.
///
/// Read directly out of `.text`-adjacent data by five of this module's naked
/// functions -- the ones with a register to spare for it. The sixth, the
/// syscall callback body, cannot afford that second register and reaches the
/// same slot through [`syscall_entry_stubs`]'s baked immediate instead; the two
/// are kept consistent by both deriving from the same key.
///
/// `0` is an unambiguous "not reserved yet" sentinel: TSD slot 0 is
/// libpthread's own `pthread_self` pointer, which `pthread_key_create` never
/// hands out.
static GUEST_STATE_TSD_BYTE_OFFSET: AtomicUsize = AtomicUsize::new(0);

/// Reserves (once per process) the pthread TSD slot this module's per-thread
/// state pointer lives in, returning its key.
///
/// This is a *second* key, independent of the one `lib.rs`'s
/// `reserve_guest_tpidr_tsd_slot` reserves for the guest's own `TPIDR_EL0`
/// shadow: that one is the *guest's* thread pointer, this one is the *host's*
/// context-switch bookkeeping, and a guest is entitled to write anything it
/// likes into its own.
///
/// Idempotent and race-free: the loser of a concurrent first call keeps its
/// key allocated rather than deleting it, because `pthread_key_delete` returns
/// the key to the pool where an unrelated `pthread_key_create` could pick it up
/// while this module is still using the winner's -- a one-key leak in a race
/// that can only happen once per process is the cheaper trade.
///
/// # Panics
///
/// Panics if `pthread_key_create` fails (genuine key exhaustion), or if the key
/// falls outside [`TSD_SLOT_COUNT`] -- both unrecoverable, and both far better
/// as a loud failure at startup than as a wild pointer in a naked callback.
fn reserve_guest_state_tsd_slot() -> libc::pthread_key_t {
    let existing = GUEST_STATE_TSD_BYTE_OFFSET.load(Ordering::Acquire);
    if existing != 0 {
        return key_from_byte_offset(existing);
    }

    let mut key: libc::pthread_key_t = 0;
    // SAFETY: `key` is a valid, uniquely-owned out-parameter. No destructor is
    // wanted: `run_thread` clears the slot itself on the way out, and the
    // pointer addresses a stack frame that is gone by thread exit anyway.
    let rc = unsafe { libc::pthread_key_create(&raw mut key, None) };
    assert_eq!(
        rc, 0,
        "failed to reserve the guest-entry per-thread-state TSD slot: \
         pthread_key_create returned {rc}"
    );
    let slot = usize::try_from(key).expect("a pthread key is never negative");
    assert!(
        slot < TSD_SLOT_COUNT,
        "pthread_key_create handed out TSD key {slot}, past the {TSD_SLOT_COUNT} \
         stubs syscall_entry_stubs emits; the table needs widening"
    );
    let byte_offset = slot * size_of::<usize>();

    match GUEST_STATE_TSD_BYTE_OFFSET.compare_exchange(
        0,
        byte_offset,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => key,
        // Another thread got there first; keep its key (see the doc comment on
        // why the loser's key is deliberately not returned to the pool).
        Err(winner) => key_from_byte_offset(winner),
    }
}

/// Inverts [`reserve_guest_state_tsd_slot`]'s `key * 8` scaling.
fn key_from_byte_offset(byte_offset: usize) -> libc::pthread_key_t {
    libc::pthread_key_t::try_from(byte_offset / size_of::<usize>())
        .expect("the reserved key round-trips through its own byte offset")
}

/// The calling thread's [`GuestThreadState`], or null if this thread is not
/// inside [`run_thread`].
///
/// Deliberately the same raw `MRS`-based direct-TSD read the naked assembly
/// does, rather than `pthread_getspecific`: `lib.rs`'s signal handlers call
/// this, and an inline three-instruction sequence with no call is
/// unambiguously async-signal-safe where a libSystem call is only safe by
/// inspection. (Both were checked to observe the same storage on this
/// hardware; see `direct_tsd_read_sees_pthread_setspecific`.)
pub(crate) fn current_guest_state() -> *mut GuestThreadState {
    let byte_offset = GUEST_STATE_TSD_BYTE_OFFSET.load(Ordering::Relaxed);
    if byte_offset == 0 {
        // No key reserved yet, so no thread can be running a guest.
        return core::ptr::null_mut();
    }
    let state: usize;
    // SAFETY: reads one pointer-sized word out of this thread's own pthread TSD
    // array at a slot `pthread_key_create` reserved for this module. The array
    // is part of the live `pthread_t` and is always mapped; the low-bit mask
    // matches libSystem's own `_os_tsd_get_base`.
    unsafe {
        core::arch::asm!(
            "mrs {base}, tpidrro_el0",
            "and {base}, {base}, #0xfffffffffffffff8",
            "ldr {state}, [{base}, {offset}]",
            base = out(reg) _,
            state = out(reg) state,
            offset = in(reg) byte_offset,
            options(nostack, readonly, preserves_flags),
        );
    }
    core::ptr::with_exposed_provenance_mut(state)
}

/// Whether the given thread state says the guest genuinely owns the CPU. Null
/// (a thread that never entered [`run_thread`]) reads as `false`.
pub(crate) fn guest_owns_cpu(state: *mut GuestThreadState) -> bool {
    if state.is_null() {
        return false;
    }
    // SAFETY: non-null here means `run_thread` published this thread's own live
    // stack-allocated state, which outlives every signal handler that can
    // observe it (the handler runs on that same thread, inside that frame).
    unsafe { (*state).owns_cpu.load(Ordering::Relaxed) }
}

/// Records a `SIGUSR2` that could not be redirected immediately, for
/// [`enter_guest_asm`] to honor at the next entry. A null state (no guest on
/// this thread) has nothing to record against and is a no-op -- the signal's
/// other job, `EINTR`-ing a blocking host call, has already happened simply by
/// being delivered.
pub(crate) fn record_pending_interrupt(state: *mut GuestThreadState) {
    if state.is_null() {
        return;
    }
    // SAFETY: as `guest_owns_cpu`.
    unsafe { (*state).pending_interrupt.store(true, Ordering::Relaxed) };
}

/// Reads the calling thread's guest FP/SIMD state in the shim-facing shape, for
/// `lib.rs`'s `ThreadProvider::get_fp_state` implementation.
///
/// Callable any time no guest is concurrently mutating it via
/// `enter_guest_asm`/the syscall callback/`exception_callback` -- i.e. whenever
/// an `EnterShim` method is running on this thread, which is the only time the
/// shim can call this, since `owns_cpu` is false throughout.
///
/// # Panics
///
/// Panics if the calling thread is not running a guest, which would mean the
/// shim asked for a guest's vector state on a thread that has none.
pub(crate) fn guest_fp_state() -> litebox::platform::FpSimdState64 {
    let state = current_guest_state();
    assert!(
        !state.is_null(),
        "get_fp_state called on a thread that is not running a guest"
    );
    // SAFETY: non-null, and not concurrently written while an `EnterShim`
    // method (and therefore this function) can run on this thread.
    let fp = unsafe { &(*state).guest_fp };
    litebox::platform::FpSimdState64 {
        v: fp.v,
        fpsr: fp.fpsr.trunc(),
        fpcr: fp.fpcr.trunc(),
    }
}

/// Writes the calling thread's guest FP/SIMD state from the shim-facing shape,
/// for `lib.rs`'s `ThreadProvider::set_fp_state` implementation (e.g. restoring
/// what a guest signal handler left in its frame on `rt_sigreturn`).
///
/// Same calling window, and same panic, as [`guest_fp_state`].
pub(crate) fn set_guest_fp_state(state: &litebox::platform::FpSimdState64) {
    let thread_state = current_guest_state();
    assert!(
        !thread_state.is_null(),
        "set_fp_state called on a thread that is not running a guest"
    );
    // SAFETY: as `guest_fp_state`.
    let fp = unsafe { &mut (*thread_state).guest_fp };
    fp.v = state.v;
    fp.fpcr = u64::from(state.fpcr);
    fp.fpsr = u64::from(state.fpsr);
}

/// Enter (or resume) the guest with the register state in `ctx`.
///
/// Saves the host's callee-saved registers, `LR` and `SP` into `state`'s host
/// save area, records `ctx` in `state`, restores every guest register from
/// `ctx`, and branches to `ctx.pc` through `X17`. It "returns" -- with
/// callee-saved registers preserved, ABI-correctly -- only when the syscall
/// callback, [`exception_callback`] or [`interrupt_callback`] restores the host
/// context, at which point `*ctx` holds the guest state at that event and the
/// return value says which kind it was (see [`GuestExit`]).
///
/// `state` is passed in rather than looked up: this function is reached by an
/// ordinary Rust call with every argument register free, so it has no need of
/// the `TPIDRRO_EL0` reach the callbacks depend on.
///
/// # Safety
///
/// `ctx` must point to a valid, writable [`PtRegs`] describing a guest context.
/// Its `pc` and `sp` may themselves be invalid guest values: entering that
/// context must route the resulting hardware fault through the guest exception
/// path rather than dereference either value inside host switch code. `state`
/// must point to this thread's own live [`GuestThreadState`], the one published
/// in its TSD slot.
#[unsafe(naked)]
unsafe extern "C" fn enter_guest_asm(ctx: *mut PtRegs, state: *mut GuestThreadState) -> u64 {
    core::arch::naked_asm!(
        // x16 holds the per-thread state until the guest-register restore below
        // reaches guest x16. The host-owned PtRegs pointer stays in x0 until the
        // final two loads, so restoring a guest context never needs to read or
        // write through its potentially-invalid sp.
        "mov  x16, x1",
        // Save host callee-saved registers, LR and SP.
        "stp  x19, x20, [x16, #0]",
        "stp  x21, x22, [x16, #16]",
        "stp  x23, x24, [x16, #32]",
        "stp  x25, x26, [x16, #48]",
        "stp  x27, x28, [x16, #64]",
        "str  x29, [x16, #80]",
        "str  x30, [x16, #88]",
        "mov  x2, sp",
        "str  x2, [x16, #96]",
        // Save the host's callee-saved FP registers and its FP control/status.
        "stp  d8,  d9,  [x16, #104]",
        "stp  d10, d11, [x16, #120]",
        "stp  d12, d13, [x16, #136]",
        "stp  d14, d15, [x16, #152]",
        "mrs  x2, fpcr",
        "str  x2, [x16, #168]",
        "mrs  x2, fpsr",
        "str  x2, [x16, #176]",
        // Restore the guest's whole vector file and FP control/status. Done
        // here, before any guest GPR is live.
        "ldp  q0,  q1,  [x16, #192]",
        "ldp  q2,  q3,  [x16, #224]",
        "ldp  q4,  q5,  [x16, #256]",
        "ldp  q6,  q7,  [x16, #288]",
        "ldp  q8,  q9,  [x16, #320]",
        "ldp  q10, q11, [x16, #352]",
        "ldp  q12, q13, [x16, #384]",
        "ldp  q14, q15, [x16, #416]",
        "ldp  q16, q17, [x16, #448]",
        "ldp  q18, q19, [x16, #480]",
        "ldp  q20, q21, [x16, #512]",
        "ldp  q22, q23, [x16, #544]",
        "ldp  q24, q25, [x16, #576]",
        "ldp  q26, q27, [x16, #608]",
        "ldp  q28, q29, [x16, #640]",
        "ldp  q30, q31, [x16, #672]",
        "ldr  x2, [x16, #704]",
        "msr  fpcr, x2",
        "ldr  x2, [x16, #712]",
        "msr  fpsr, x2",
        // Record the live PtRegs pointer for the callback, and restore the guest
        // SP without touching memory through it. x0 remains the host-owned
        // PtRegs base until the final guest-x0 load.
        "str  x0, [x16, #720]",
        "ldr  x1, [x0, #248]",       // guest sp
        "ldr  x2, [x0, #264]",       // pstate -> NZCV
        "msr  nzcv, x2",
        "mov  sp, x1",
        // switch_to_guest_start: from here on, a SIGUSR2 arriving must not be
        // treated as "genuinely executing guest code" even once owns_cpu reads
        // true below -- interrupted_pc_is_in_guest_entry_restore checks this
        // exact range (up to switch_to_guest_end) for that reason. See
        // `lib.rs`'s `interrupt_signal_handler` doc comment for the full
        // four-case dispatch this label range is one input to.
        //
        // `_`-prefixed and `.globl`, matching Darwin's (unlike Linux's)
        // leading-underscore C symbol convention -- verified against this
        // build by `interrupted_pc_is_in_guest_entry_restore`'s own hardware
        // test, not merely assumed.
        ".globl _switch_to_guest_start",
        "_switch_to_guest_start:",
        // Mark the guest as genuinely owning the CPU from here on (see
        // GuestThreadState::owns_cpu's doc comment for why this is not placed
        // immediately before the branch instead).
        "mov  w1, #1",
        "strb w1, [x16, #728]",
        // Re-check pending_interrupt immediately after opening the "owns"
        // window, before restoring any guest register -- mirrors
        // litebox_platform_linux_userland::switch_to_guest's own pending-
        // interrupt check placed right after its `in_guest := 1` store (see
        // GuestThreadState::pending_interrupt's doc comment for why this
        // re-check exists at all). ctx (x0) is untouched, so abandoning the
        // entry here needs no capture -- interrupt_callback is reached with
        // `*ctx` exactly as the caller left it, and re-derives the per-thread
        // state itself.
        "ldrb w1, [x16, #729]",
        "cbz  w1, 92f",
        "strb wzr, [x16, #729]",
        "strb wzr, [x16, #728]",
        "adrp x1, {interrupt_cb}@PAGE",
        "add  x1, x1, {interrupt_cb}@PAGEOFF",
        "br   x1",
        "92:",
        // Restore x1..x30 except x17 (x0 and x17 handled last; skip
        // regs[17]). x17, not x16, is now the sacrificed branch vehicle --
        // see the comment on the final branch below for why.
        "ldr  x1,  [x0, #8]",
        "ldp  x2,  x3,  [x0, #16]",
        "ldp  x4,  x5,  [x0, #32]",
        "ldp  x6,  x7,  [x0, #48]",
        "ldp  x8,  x9,  [x0, #64]",
        "ldp  x10, x11, [x0, #80]",
        "ldp  x12, x13, [x0, #96]",
        "ldp  x14, x15, [x0, #112]",
        "ldr  x16, [x0, #128]",
        "ldp  x18, x19, [x0, #144]",
        "ldp  x20, x21, [x0, #160]",
        "ldp  x22, x23, [x0, #176]",
        "ldp  x24, x25, [x0, #192]",
        "ldp  x26, x27, [x0, #208]",
        "ldp  x28, x29, [x0, #224]",
        "ldr  x30, [x0, #240]",
        // Load the guest PC into the deliberately-sacrificed x17 branch vehicle
        // while x0 still addresses host-owned PtRegs, then load guest x0 through
        // that same base. `ldr x0, [x0]` computes its address before replacing
        // the base register, so neither instruction touches guest memory.
        "ldr  x17, [x0, #256]",
        "ldr  x0,  [x0, #0]",
        "br   x17",
        // switch_to_guest_end: a label, never reached by falling through (the
        // branch above always diverts first) -- its only purpose is to give
        // interrupted_pc_is_in_guest_entry_restore an end address for the
        // range starting at switch_to_guest_start.
        ".globl _switch_to_guest_end",
        "_switch_to_guest_end:",
        interrupt_cb = sym interrupt_callback,
    )
}

/// Which of the syscall callback, [`exception_callback`] or
/// [`interrupt_callback`] restored the host context, i.e. what
/// [`enter_guest_asm`]'s return value means. `run_thread`'s loop dispatches on
/// this instead of always assuming a syscall -- the second return path
/// [`Self::Interrupt`] needed on top of the original syscall/exception split.
enum GuestExit {
    Syscall,
    Exception,
    Interrupt,
}

impl GuestExit {
    /// Decodes [`enter_guest_asm`]'s return value. All three callbacks set
    /// exactly `0`, `1` or `2`, so anything else would mean the asm and this
    /// decoder have drifted apart -- a build-time bug, not a runtime condition
    /// to handle gracefully.
    fn from_asm_return(value: u64) -> Self {
        match value {
            0 => Self::Syscall,
            1 => Self::Exception,
            2 => Self::Interrupt,
            _ => unreachable!("enter_guest_asm returned an undefined GuestExit code {value}"),
        }
    }
}

/// The per-TSD-slot entry stubs a rewritten guest's `SVC` gate branches to,
/// followed by the shared callback body they all reach.
///
/// [`syscall_entry_point`] picks the stub matching this process's reserved key
/// and [`litebox::platform::SystemInfoProvider::get_syscall_entry_point`] hands
/// *that* address to the loader, which writes it into the trampoline the
/// rewriter appended to the guest image. Stub `N` resolves this thread's
/// [`GuestThreadState`] out of pthread TSD slot `N` using its single free
/// register and falls into the shared body; see this module's own doc comment
/// for why a table of baked immediates is what it takes to do that with one
/// register and no dependence on the guest's `SP`.
///
/// On entry to the body the [`litebox_syscall_rewriter`] `SVC` gate has: saved
/// the guest `X16` at `[SP]` and the post-`SVC` return address at `[SP, #8]`,
/// decremented `SP` by 16, and left every other guest register (and `NZCV`)
/// intact -- and the stub has replaced the now-dead `X16` with the per-thread
/// state pointer. The body captures that state into the live [`PtRegs`],
/// restores the host context, and returns into the run loop.
///
/// The stubs branch to the body with a plain `B` to a *local* (`L`-prefixed)
/// label in the same assembly fragment, so it is resolved by the assembler with
/// no relocation and no possibility of a linker-inserted veneer -- which would
/// clobber `X16`, the one register carrying the whole mechanism.
///
/// # Safety
///
/// Reached only from a guest `SVC` gate with the register/stack state described
/// above; not callable as an ordinary function.
#[unsafe(naked)]
unsafe extern "C" fn syscall_entry_stubs() {
    core::arch::naked_asm!(
        // syscall_callback_start/_end bracket the stubs *and* the body, used by
        // interrupted_pc_is_in_guest_exit_prologue. Only the stub plus the
        // first instruction of the body (before owns_cpu is cleared) are the
        // window that check actually needs to distinguish -- the rest already
        // reads owns_cpu false by the time it runs, so `lib.rs`'s
        // `interrupt_signal_handler` never reaches the PC-range check for it
        // (see that function's case-1 priority ordering); using the whole
        // range is simpler than a second, tighter label pair and no less
        // correct.
        ".globl _syscall_callback_start",
        "_syscall_callback_start:",
        ".set litebox_tsd_slot, 0",
        ".rept {slots}",
        "mrs  x16, tpidrro_el0",
        "and  x16, x16, #0xfffffffffffffff8",
        "ldr  x16, [x16, #(litebox_tsd_slot * 8)]",
        "b    Lsyscall_callback_body",
        ".set litebox_tsd_slot, litebox_tsd_slot + 1",
        ".endr",
        "Lsyscall_callback_body:",
        // Clear ownership before touching anything else -- see
        // GuestThreadState::owns_cpu's doc comment. This is the very first
        // memory write the body makes, and it targets this thread's own state,
        // never the (possibly-corrupt) guest sp read below.
        "strb wzr, [x16, #728]",
        // Swap the state pointer for the destination PtRegs (host-owned, set by
        // enter_guest_asm) and capture every guest GPR straight into it through
        // this same dedicated base register, x16, held for the whole capture.
        // sp is deliberately never used as the capture buffer -- it still holds
        // the guest's own (possibly-corrupt) value at this point -- so nothing
        // below can fault by dereferencing it, other than the two gate-stashed-
        // word reads further down.
        "ldr  x16, [x16, #720]",
        "stp  x0,  x1,  [x16, #0]",
        "stp  x2,  x3,  [x16, #16]",
        "stp  x4,  x5,  [x16, #32]",
        "stp  x6,  x7,  [x16, #48]",
        "stp  x8,  x9,  [x16, #64]",
        "stp  x10, x11, [x16, #80]",
        "stp  x12, x13, [x16, #96]",
        "stp  x14, x15, [x16, #112]",
        // The SVC gate stashed the guest's real x16 at [sp] and the post-SVC
        // return address at [sp, #8] before jumping here (having decremented
        // sp by 16 first) -- the only guest-memory reads in this function, and
        // the only reason a bad guest sp can still fault inside it. x9 and x11
        // are free to use as scratch: their real guest values are already
        // captured above. owns_cpu is already false by this point (see above),
        // so if either fault, fault_handler's fallback (today's behavior: the
        // process dies) runs, never guest delivery.
        "80:",
        "ldr  x9,  [sp]",
        "ldr  x11, [sp, #8]",
        "81:",
        ".pushsection __TEXT,__ex_table,regular,no_dead_strip",
        ".balign 4",
        ".long 80b - .",
        ".long 81b - .",
        ".long {abort} - .",
        ".popsection",
        "str  x9,  [x16, #128]",
        "str  x17, [x16, #136]",
        "stp  x18, x19, [x16, #144]",
        "stp  x20, x21, [x16, #160]",
        "stp  x22, x23, [x16, #176]",
        "stp  x24, x25, [x16, #192]",
        "stp  x26, x27, [x16, #208]",
        "stp  x28, x29, [x16, #224]",
        "str  x30, [x16, #240]",
        "str  x11, [x16, #256]",     // pc = post-SVC return address = guest pc
        "add  x9, sp, #16",          // sp = guest's pre-gate sp
        "str  x9, [x16, #248]",
        "mrs  x9, nzcv",
        "str  x9, [x16, #264]",      // pstate
        // The shim reads the syscall number from `syscallno`, not from `regs[8]`
        // -- that is where a Linux kernel entry path records it, and the shim is
        // written against `pt_regs`. Likewise `orig_x0` keeps the first argument,
        // which the return value overwrites in `regs[0]`. Neither is a copy of a
        // register the guest can see, so both have to be filled here or the
        // dispatcher reads whatever the buffer happened to hold. x0 and x8 are
        // still exactly their original guest values: nothing above wrote them.
        "str  x0, [x16, #272]",      // orig_x0
        "str  w8, [x16, #280]",      // syscallno (32-bit field)
        // Re-derive the per-thread state. Every guest GPR is captured by now,
        // so x9/x10 are ordinary scratch and the two-register lookup the entry
        // stub could not afford is free here.
        "mrs  x9, tpidrro_el0",
        "and  x9, x9, #0xfffffffffffffff8",
        "adrp x10, {tsd_off}@PAGE",
        "add  x10, x10, {tsd_off}@PAGEOFF",
        "ldr  x10, [x10]",
        "ldr  x9, [x9, x10]",
        // Capture the guest's whole vector file and FP control/status before any
        // host code runs, since the host is free to use every vector register.
        "stp  q0,  q1,  [x9, #192]",
        "stp  q2,  q3,  [x9, #224]",
        "stp  q4,  q5,  [x9, #256]",
        "stp  q6,  q7,  [x9, #288]",
        "stp  q8,  q9,  [x9, #320]",
        "stp  q10, q11, [x9, #352]",
        "stp  q12, q13, [x9, #384]",
        "stp  q14, q15, [x9, #416]",
        "stp  q16, q17, [x9, #448]",
        "stp  q18, q19, [x9, #480]",
        "stp  q20, q21, [x9, #512]",
        "stp  q22, q23, [x9, #544]",
        "stp  q24, q25, [x9, #576]",
        "stp  q26, q27, [x9, #608]",
        "stp  q28, q29, [x9, #640]",
        "stp  q30, q31, [x9, #672]",
        "mrs  x10, fpcr",
        "str  x10, [x9, #704]",
        "mrs  x10, fpsr",
        "str  x10, [x9, #712]",
        // Restore host callee-saved registers, LR and SP, then return into the
        // run loop (as though enter_guest_asm had returned), reporting a syscall.
        "ldp  x19, x20, [x9, #0]",
        "ldp  x21, x22, [x9, #16]",
        "ldp  x23, x24, [x9, #32]",
        "ldp  x25, x26, [x9, #48]",
        "ldp  x27, x28, [x9, #64]",
        "ldr  x29, [x9, #80]",
        "ldr  x30, [x9, #88]",
        // Hand the host back its callee-saved FP registers and FP control/status.
        "ldp  d8,  d9,  [x9, #104]",
        "ldp  d10, d11, [x9, #120]",
        "ldp  d12, d13, [x9, #136]",
        "ldp  d14, d15, [x9, #152]",
        "ldr  x10, [x9, #168]",
        "msr  fpcr, x10",
        "ldr  x10, [x9, #176]",
        "msr  fpsr, x10",
        "ldr  x10, [x9, #96]",
        "mov  sp, x10",
        "mov  x0, #0",
        "ret",
        // syscall_callback_end: never reached (the `ret` above always leaves
        // first); see syscall_callback_start's comment.
        ".globl _syscall_callback_end",
        "_syscall_callback_end:",
        slots = const TSD_SLOT_COUNT,
        tsd_off = sym GUEST_STATE_TSD_BYTE_OFFSET,
        abort = sym abort_on_boundary_stack_fault,
    )
}

/// The address a guest's `SVC` gate must branch to on this process: the
/// [`syscall_entry_stubs`] stub for the pthread TSD slot this process reserved
/// for its per-thread guest-entry state.
///
/// Reserves the slot on first call, so this is safe to ask for before any guest
/// thread starts (which is exactly when the loader asks).
pub(crate) fn syscall_entry_point() -> usize {
    let key = reserve_guest_state_tsd_slot();
    let slot = usize::try_from(key).expect("a pthread key is never negative");
    // `reserve_guest_state_tsd_slot` already rejected an out-of-range key; this
    // is the second half of that same invariant, stated where the arithmetic
    // that depends on it happens.
    assert!(slot < TSD_SLOT_COUNT, "TSD slot {slot} has no entry stub");
    (syscall_entry_stubs as *const () as usize) + slot * TSD_STUB_BYTES
}

/// The recovery target [`lib.rs`'s `fault_handler`] redirects a genuine guest
/// hardware fault to, once [`prepare_exception_delivery`] has already copied
/// the guest's captured register file (from the signal `mcontext`, not from
/// any guest-stack dereference) into the live [`PtRegs`] and filled in
/// `pending_exception_info`. Unlike the syscall callback, this never touches
/// guest memory at all -- everything it needs was already captured in Rust --
/// so it is simply that callback's host-state-restore tail, reporting exception
/// (`1`) instead of syscall (`0`), prefixed by its own per-thread-state lookup
/// (free to do the two-register way: it is reached by a `pc` redirect, so every
/// register is dead).
///
/// # Safety
///
/// Reached only via a `pc` redirect from `fault_handler`, with `owns_cpu`
/// already cleared and the live [`PtRegs`]/`pending_exception_info` already
/// populated by [`prepare_exception_delivery`]; not callable as an ordinary
/// function.
#[unsafe(naked)]
unsafe extern "C" fn exception_callback() {
    core::arch::naked_asm!(
        "mov x0, #1",
        "b {return_callback}",
        return_callback = sym signal_return_callback,
    )
}

#[unsafe(naked)]
unsafe extern "C" fn faulted_syscall_callback() {
    core::arch::naked_asm!(
        "mov x0, #0",
        "b {return_callback}",
        return_callback = sym signal_return_callback,
    )
}

#[unsafe(naked)]
unsafe extern "C" fn signal_return_callback() {
    core::arch::naked_asm!(
        "mrs  x1, tpidrro_el0",
        "and  x1, x1, #0xfffffffffffffff8",
        "adrp x2, {tsd_off}@PAGE",
        "add  x2, x2, {tsd_off}@PAGEOFF",
        "ldr  x2, [x2]",
        "ldr  x1, [x1, x2]",
        "ldp  x19, x20, [x1, #0]",
        "ldp  x21, x22, [x1, #16]",
        "ldp  x23, x24, [x1, #32]",
        "ldp  x25, x26, [x1, #48]",
        "ldp  x27, x28, [x1, #64]",
        "ldr  x29, [x1, #80]",
        "ldr  x30, [x1, #88]",
        "ldp  d8,  d9,  [x1, #104]",
        "ldp  d10, d11, [x1, #120]",
        "ldp  d12, d13, [x1, #136]",
        "ldp  d14, d15, [x1, #152]",
        "ldr  x2, [x1, #168]",
        "msr  fpcr, x2",
        "ldr  x2, [x1, #176]",
        "msr  fpsr, x2",
        "ldr  x2, [x1, #96]",
        "mov  sp, x2",
        "ret",
        tsd_off = sym GUEST_STATE_TSD_BYTE_OFFSET,
    )
}

/// The recovery target `lib.rs`'s `interrupt_signal_handler` redirects an
/// interrupted guest thread to, once either [`prepare_interrupt_delivery`]
/// (genuinely-executing-guest case) has captured state or
/// [`abandon_guest_entry_for_interrupt`] (mid-restore case) has decided no
/// capture is needed. Identical in structure to [`exception_callback`],
/// reporting interrupt (`2`) instead of exception (`1`) or syscall (`0`).
///
/// Also reached directly by [`enter_guest_asm`]'s pending-interrupt re-check,
/// which is why it re-derives the per-thread state rather than expecting it in
/// a register: the two callers arrive with completely different register state
/// and only the `TPIDRRO_EL0` reach is common to both.
///
/// # Safety
///
/// Reached only via a `pc` redirect from `interrupt_signal_handler` or from
/// [`enter_guest_asm`]'s own re-check, with `owns_cpu` already cleared and the
/// live [`PtRegs`] already either left as the caller's still-accurate context
/// or freshly populated; not callable as an ordinary function.
#[unsafe(naked)]
unsafe extern "C" fn interrupt_callback() {
    core::arch::naked_asm!(
        "mrs  x1, tpidrro_el0",
        "and  x1, x1, #0xfffffffffffffff8",
        "adrp x2, {tsd_off}@PAGE",
        "add  x2, x2, {tsd_off}@PAGEOFF",
        "ldr  x2, [x2]",
        "ldr  x1, [x1, x2]",
        "ldp  x19, x20, [x1, #0]",
        "ldp  x21, x22, [x1, #16]",
        "ldp  x23, x24, [x1, #32]",
        "ldp  x25, x26, [x1, #48]",
        "ldp  x27, x28, [x1, #64]",
        "ldr  x29, [x1, #80]",
        "ldr  x30, [x1, #88]",
        "ldp  d8,  d9,  [x1, #104]",
        "ldp  d10, d11, [x1, #120]",
        "ldp  d12, d13, [x1, #136]",
        "ldp  d14, d15, [x1, #152]",
        "ldr  x2, [x1, #168]",
        "msr  fpcr, x2",
        "ldr  x2, [x1, #176]",
        "msr  fpsr, x2",
        "ldr  x2, [x1, #96]",
        "mov  sp, x2",
        "mov  x0, #2",
        "ret",
        tsd_off = sym GUEST_STATE_TSD_BYTE_OFFSET,
    )
}

/// aarch64 Linux's `__NR_rt_sigreturn`, hardcoded into [`sigreturn_trampoline`]
/// because the guest never sets `x8` on the way in (there is no real `SVC`,
/// so no C library gets a chance to). Verified against the vendored
/// `syscalls-0.6.18` crate source
/// (`src/arch/aarch64.rs:286`, `rt_sigreturn = 139`) -- the same crate
/// `litebox_common_linux::SyscallRequest::try_from_raw` decodes `PtRegs::syscallno`
/// through, so this is guaranteed to route to `Sysno::rt_sigreturn` there.
const AARCH64_RT_SIGRETURN: u32 = 139;

/// This platform's own sigreturn trampoline: what
/// [`litebox::platform::SystemInfoProvider::get_sigreturn_trampoline_address`]
/// reports, and what `litebox_shim_linux` installs as a guest signal handler's
/// return address (`x30`) when the guest registered the handler without
/// `SA_RESTORER`. There is no vDSO on macOS to fall back to the way a real
/// Linux kernel does (see `darwin.rs`'s and `lib.rs`'s `get_vdso_address`
/// docs), so this *is* the fallback -- reached the same way the syscall
/// callback is, by handing a host code address to a guest-controlled register
/// (there `x16` via the rewriter's gate, here `x30` via the signal frame
/// `litebox_shim_linux` builds), an "absolute address" reachable from any guest
/// regardless of branch-range limits (see `litebox_syscall_rewriter::arm64`'s
/// "Signal returns" module-doc section, which anticipated exactly this).
///
/// Unlike the syscall callback, this never touches guest memory at all, and
/// needs no exception-table entry: a real `SVC` gate stashes the guest's `x16`
/// and a return address below `sp` because it has no free register to carry
/// them in, but this trampoline is reached directly by `RET` (no gate ran),
/// so nothing needs recovering from the guest stack -- which also means every
/// register is free here, so it resolves its own per-thread state the
/// two-register way rather than needing an entry-stub table of its own. It
/// captures only `sp` (via the real `SP` register, exactly as the guest's `ret`
/// left it) and sets `syscallno` to [`AARCH64_RT_SIGRETURN`] -- deliberately
/// capturing *no other register*, unlike every other guest-exit path in this
/// file. This is safe only because of what `sys_rt_sigreturn`/`restore_sigcontext`
/// (`litebox_shim_linux/src/syscalls/signal/{mod.rs,aarch64.rs}`) actually do
/// with the `PtRegs` this hands them: `Sysno::rt_sigreturn` takes no register
/// arguments (confirmed against `SyscallRequest::try_from_raw`'s dispatch, which
/// extracts zero fields for it), the frame is located purely from `ctx.sp`, and
/// every other field (`regs`, `pc`, `pstate`) is overwritten wholesale from the
/// frame's saved `sigcontext` before anything downstream reads it -- including
/// `regs[0]`, which the generic "write the syscall result into `x0`" step then
/// re-writes with the exact value `restore_sigcontext` just placed there,
/// making that generic step a no-op for this syscall specifically. A stale
/// `pc`/`regs`/`pstate` left over from whatever this `PtRegs` last held is
/// therefore never observed.
///
/// # Safety
///
/// Reached only via a guest `RET` with `x30` holding this function's own
/// address (installed by `litebox_shim_linux` as a signal frame's return
/// slot) and `owns_cpu` genuinely true; not callable as an ordinary function.
#[unsafe(naked)]
pub(crate) unsafe extern "C" fn sigreturn_trampoline() {
    core::arch::naked_asm!(
        // sigreturn_trampoline_start: covers this whole function, same
        // reasoning as syscall_callback_start.
        ".globl _sigreturn_trampoline_start",
        "_sigreturn_trampoline_start:",
        // Resolve this thread's state, then clear ownership before touching
        // anything else -- see GuestThreadState::owns_cpu's doc comment. The
        // five instructions ahead of that clear read only a system register and
        // this process's own TSD array, never guest memory, so they cannot
        // fault; an interrupt landing on them is screened by this function's
        // own PC range (interrupted_pc_is_in_guest_exit_prologue).
        "mrs  x9, tpidrro_el0",
        "and  x9, x9, #0xfffffffffffffff8",
        "adrp x10, {tsd_off}@PAGE",
        "add  x10, x10, {tsd_off}@PAGEOFF",
        "ldr  x10, [x10]",
        "ldr  x9, [x9, x10]",
        "strb wzr, [x9, #728]",
        // Load the destination PtRegs (host-owned, set by enter_guest_asm).
        "ldr  x10, [x9, #720]",
        // sp: the guest's real SP, exactly as its own `ret` left it (SP
        // cannot be a direct STR source operand, hence the mov through x11).
        "mov  x11, sp",
        "str  x11, [x10, #248]",
        // syscallno: force dispatch to sys_rt_sigreturn regardless of
        // whatever this guest's x8 last held (no real SVC ran).
        "movz w11, #{rt_sigreturn}",
        "str  w11, [x10, #280]",
        // Restore host state and return reporting a syscall (0), exactly like
        // the syscall callback's own tail, so run_thread's loop calls
        // shim.syscall -- which dispatches sys_rt_sigreturn purely from the
        // sp/syscallno just written (see this function's own doc comment for
        // why nothing else needs capturing).
        "ldp  x19, x20, [x9, #0]",
        "ldp  x21, x22, [x9, #16]",
        "ldp  x23, x24, [x9, #32]",
        "ldp  x25, x26, [x9, #48]",
        "ldp  x27, x28, [x9, #64]",
        "ldr  x29, [x9, #80]",
        "ldr  x30, [x9, #88]",
        "ldp  d8,  d9,  [x9, #104]",
        "ldp  d10, d11, [x9, #120]",
        "ldp  d12, d13, [x9, #136]",
        "ldp  d14, d15, [x9, #152]",
        "ldr  x10, [x9, #168]",
        "msr  fpcr, x10",
        "ldr  x10, [x9, #176]",
        "msr  fpsr, x10",
        "ldr  x10, [x9, #96]",
        "mov  sp, x10",
        "mov  x0, #0",
        "ret",
        // sigreturn_trampoline_end: never reached, same reasoning as
        // syscall_callback_end.
        ".globl _sigreturn_trampoline_end",
        "_sigreturn_trampoline_end:",
        tsd_off = sym GUEST_STATE_TSD_BYTE_OFFSET,
        rt_sigreturn = const AARCH64_RT_SIGRETURN,
    )
}

/// Reached only via the exception-table entry emitted inline within
/// [`syscall_entry_stubs`]'s callback body: a fault at the two instructions
/// where this platform's own switch code must read the words the rewritten
/// `SVC` gate stashed at a guest-controlled `sp`, after the guest has stopped.
/// `lib.rs`'s `fault_handler` always checks the exception table before
/// `owns_cpu`, so a fault here is redirected to this recovery point instead of
/// ever being weighed as a candidate for guest delivery -- the `pc`/`x30` a
/// naive check would otherwise see point inside this platform's own binary,
/// which is exactly the ASLR-disclosure/return-to-host-code hazard this file
/// exists to avoid. Reaching here means the gate completed its stores but the
/// mapping disappeared before the callback's reads; a loud, unambiguous abort
/// is safer than guessing whose fault it was.
#[unsafe(naked)]
unsafe extern "C" fn abort_on_boundary_stack_fault() -> ! {
    core::arch::naked_asm!(
        // Reached by a `pc` redirect, so every register is free; resolve this
        // thread's state the ordinary two-register way.
        "mrs  x2, tpidrro_el0",
        "and  x2, x2, #0xfffffffffffffff8",
        "adrp x0, {tsd_off}@PAGE",
        "add  x0, x0, {tsd_off}@PAGEOFF",
        "ldr  x0, [x0]",
        "ldr  x2, [x2, x0]",
        // Belt-and-suspenders: this path is headed for a fatal abort
        // regardless, but clearing owns_cpu here too (rather than leaving it
        // however it read at the fault) closes the otherwise-real possibility
        // of a SIGUSR2 landing in the couple of instructions between here and
        // the abort call and misreading a stale `true`.
        "strb wzr, [x2, #728]",
        "ldr  x1, [x2, #96]",
        "mov  sp, x1",
        "b {abort}",
        tsd_off = sym GUEST_STATE_TSD_BYTE_OFFSET,
        abort = sym abort_boundary_stack_fault,
    )
}

/// The Rust half of [`abort_on_boundary_stack_fault`], once a valid (host) `sp`
/// has been restored.
extern "C" fn abort_boundary_stack_fault() -> ! {
    // A raw abort, not a Rust panic: unwinding out of a function reached by a
    // hand-redirected program counter (never a real call site, so no unwind
    // table covers the jump that got here) would corrupt the process, and
    // this condition is meant to be unmistakable on stderr either way.
    eprintln!(
        "litebox_platform_macos_userland: a fault landed on the guest/host \
         entry-exit boundary's own instructions rather than genuine guest \
         code; aborting instead of guessing which side owns it"
    );
    std::process::abort()
}

/// Delivers a genuine guest hardware fault as a
/// [`litebox::shim::EnterShim::exception`] event. Called by `lib.rs`'s
/// `fault_handler` only after its exception-table check has already missed
/// and `state`'s `owns_cpu` reads true (so this instant's `pc` is guest code,
/// not this platform's own switch code -- see that field's doc comment for why
/// the ordering matters).
///
/// Copies the guest's captured GPRs/`SP`/`PC`/`PSTATE` straight from
/// `thread_state` into the run loop's live [`PtRegs`] (never re-deriving them
/// from the guest's own stack, unlike the syscall callback -- the kernel already
/// captured the true hardware state into `thread_state` at the moment of the
/// fault, a strictly more trustworthy source than anything this function could
/// read back off guest memory), refreshes the guest FP state from `neon_state`
/// for the same reason (the kernel's own capture, not whatever it held from the
/// guest's last syscall), records `info` for [`exception_callback`] to hand to
/// the run loop, clears the ownership flag, and returns the address the caller
/// should redirect the faulting `pc` to.
///
/// # Safety
///
/// Must be called with `state` this thread's own live [`GuestThreadState`], its
/// `owns_cpu` genuinely true, and `thread_state`/`neon_state` genuinely
/// describing the interrupted guest, per the caller's own exception-table-then-
/// flag check.
pub(crate) unsafe fn prepare_exception_delivery(
    state: *mut GuestThreadState,
    thread_state: &crate::darwin::ArmThreadState64,
    neon_state: &crate::darwin::ArmNeonState64,
    info: litebox::shim::ExceptionInfo,
) -> usize {
    // SAFETY: the caller's precondition -- `state` is this thread's own live
    // state, published by `run_thread` on the frame this signal interrupted.
    let state = unsafe { &mut *state };
    // SAFETY: `owns_cpu` was true (the caller's precondition), so `live_ptregs`
    // points at this thread's live `PtRegs`.
    let live = unsafe { &mut *state.live_ptregs };
    for (dst, src) in live.regs[..29].iter_mut().zip(thread_state.x.iter()) {
        *dst = src.trunc();
    }
    live.regs[29] = thread_state.fp.trunc();
    live.regs[30] = thread_state.lr.trunc();
    live.sp = thread_state.sp.trunc();
    live.pc = thread_state.pc.trunc();
    live.pstate = u64::from(thread_state.cpsr);
    live.orig_x0 = live.regs[0];
    // No syscall is in flight at a hardware fault, matching the kernel's own
    // `NO_SYSCALL` convention `litebox_shim_linux` relies on elsewhere.
    live.syscallno = -1;

    // NB: the "guest fault: captured register state" trace this function used
    // to emit here now lives in [`run_thread`]'s `GuestExit::Exception` arm.
    // Nothing async-signal-unsafe may run here: this function is called from
    // `lib.rs`'s `fault_handler`, i.e. from inside a POSIX signal handler. See
    // that call site's comment for the full reasoning and for why moving it
    // loses no information.

    state.guest_fp.v = neon_state.v;
    state.guest_fp.fpsr = u64::from(neon_state.fpsr);
    state.guest_fp.fpcr = u64::from(neon_state.fpcr);

    state.pending_exception_info = info;

    state.owns_cpu.store(false, Ordering::Relaxed);

    exception_callback as *const () as usize
}

pub(crate) unsafe fn prepare_faulted_syscall_delivery(
    state: *mut GuestThreadState,
    thread_state: &crate::darwin::ArmThreadState64,
    neon_state: &crate::darwin::ArmNeonState64,
    continuation: usize,
) -> usize {
    let state = unsafe { &mut *state };
    let live = unsafe { &mut *state.live_ptregs };
    for (dst, src) in live.regs[..29].iter_mut().zip(thread_state.x.iter()) {
        *dst = src.trunc();
    }
    live.regs[29] = thread_state.fp.trunc();
    live.regs[30] = thread_state.lr.trunc();
    let interrupted_sp: usize = thread_state.sp.trunc();
    live.sp = interrupted_sp.wrapping_add(16);
    live.pc = continuation;
    live.pstate = u64::from(thread_state.cpsr);
    live.orig_x0 = live.regs[0];
    let syscallno: u32 = live.regs[8].trunc();
    live.syscallno = syscallno.cast_signed();

    state.guest_fp.v = neon_state.v;
    state.guest_fp.fpsr = u64::from(neon_state.fpsr);
    state.guest_fp.fpcr = u64::from(neon_state.fpcr);
    state.owns_cpu.store(false, Ordering::Relaxed);

    faulted_syscall_callback as *const () as usize
}

// Address markers this file's own naked `asm!` blocks define (see
// `enter_guest_asm`'s `switch_to_guest_start`/`_end`, `syscall_entry_stubs`'s
// `syscall_callback_start`/`_end` and `sigreturn_trampoline`'s
// `sigreturn_trampoline_start`/`_end`), never called -- only their addresses
// are taken, by `interrupted_pc_is_in_guest_entry_restore`/
// `interrupted_pc_is_in_guest_exit_prologue` below.
unsafe extern "C" {
    fn switch_to_guest_start();
    fn switch_to_guest_end();
    fn syscall_callback_start();
    fn syscall_callback_end();
    fn sigreturn_trampoline_start();
    fn sigreturn_trampoline_end();
}

/// Whether an interrupted `pc` falls inside [`enter_guest_asm`]'s own
/// restore range -- "mid-restoring a [`PtRegs`] that is still authoritative,"
/// in `lib.rs`'s `interrupt_signal_handler` doc comment's terms. Used only
/// while `owns_cpu` already reads true (that flag is checked first, same
/// ordering as `fault_handler`'s exception-table-before-flag priority); this
/// function does not re-check it.
pub(crate) fn interrupted_pc_is_in_guest_entry_restore(pc: usize) -> bool {
    let start = switch_to_guest_start as *const () as usize;
    let end = switch_to_guest_end as *const () as usize;
    (start..end).contains(&pc)
}

/// Whether an interrupted `pc` falls inside [`syscall_entry_stubs`]'s (stubs
/// *and* shared callback body) or [`sigreturn_trampoline`]'s own address range
/// -- the exit-side counterpart of
/// [`interrupted_pc_is_in_guest_entry_restore`]. Only each entry stub plus the
/// first instruction of the body, and the first few instructions of the
/// trampoline, are the genuine hazard window (before `owns_cpu` is cleared);
/// the rest of each range is screened out by that flag already reading false by
/// the time `pc` lands there, so `interrupt_signal_handler` never reaches this
/// check for it. Using the whole range is deliberately imprecise in the
/// caller's favor: it can only make this function return `true` in cases where
/// the flag-based check would already have returned early, never the reverse.
pub(crate) fn interrupted_pc_is_in_guest_exit_prologue(pc: usize) -> bool {
    let syscall_start = syscall_callback_start as *const () as usize;
    let syscall_end = syscall_callback_end as *const () as usize;
    let sigreturn_start = sigreturn_trampoline_start as *const () as usize;
    let sigreturn_end = sigreturn_trampoline_end as *const () as usize;
    (syscall_start..syscall_end).contains(&pc) || (sigreturn_start..sigreturn_end).contains(&pc)
}

/// Delivers a genuine guest interrupt (`SIGUSR2` arriving while the guest is
/// truly executing, not mid-switch) as a [`litebox::shim::EnterShim::interrupt`]
/// event. Called by `lib.rs`'s `interrupt_signal_handler` only after
/// `owns_cpu` reads true and `pc` falls outside every switch-code range (see
/// [`interrupted_pc_is_in_guest_entry_restore`]/
/// [`interrupted_pc_is_in_guest_exit_prologue`]).
///
/// Structurally [`prepare_exception_delivery`] minus the [`ExceptionInfo`]:
/// same register/vector-state copy from the kernel's own captured `mcontext`,
/// same ownership-flag clear, same "return the recovery address" contract.
/// There is no `pending_exception_info`-equivalent to fill in --
/// [`litebox::shim::EnterShim::interrupt`] takes only a `ctx`, no side
/// channel.
///
/// [`ExceptionInfo`]: litebox::shim::ExceptionInfo
///
/// # Safety
///
/// Must be called with `state` this thread's own live [`GuestThreadState`], its
/// `owns_cpu` genuinely true, and `thread_state`/`neon_state` genuinely
/// describing the interrupted guest, and with `pc` already confirmed outside
/// every switch-code range, per the caller's own checks.
pub(crate) unsafe fn prepare_interrupt_delivery(
    state: *mut GuestThreadState,
    thread_state: &crate::darwin::ArmThreadState64,
    neon_state: &crate::darwin::ArmNeonState64,
) -> usize {
    // SAFETY: the caller's precondition, as in `prepare_exception_delivery`.
    let state = unsafe { &mut *state };
    // SAFETY: `owns_cpu` was true (the caller's precondition), so `live_ptregs`
    // points at this thread's live `PtRegs`.
    let live = unsafe { &mut *state.live_ptregs };
    for (dst, src) in live.regs[..29].iter_mut().zip(thread_state.x.iter()) {
        *dst = src.trunc();
    }
    live.regs[29] = thread_state.fp.trunc();
    live.regs[30] = thread_state.lr.trunc();
    live.sp = thread_state.sp.trunc();
    live.pc = thread_state.pc.trunc();
    live.pstate = u64::from(thread_state.cpsr);
    live.orig_x0 = live.regs[0];
    // No syscall is in flight at an interrupt either, same NO_SYSCALL
    // convention as prepare_exception_delivery.
    live.syscallno = -1;

    // NB: the "guest interrupt: captured register state" trace this function
    // used to emit here now lives in [`run_thread`]'s `GuestExit::Interrupt`
    // arm, for the same async-signal-safety reason spelled out in
    // [`prepare_exception_delivery`] and at that call site: this function runs
    // inside `lib.rs`'s `interrupt_signal_handler`.

    state.guest_fp.v = neon_state.v;
    state.guest_fp.fpsr = u64::from(neon_state.fpsr);
    state.guest_fp.fpcr = u64::from(neon_state.fpcr);

    state.owns_cpu.store(false, Ordering::Relaxed);

    interrupt_callback as *const () as usize
}

/// Abandons an in-flight [`enter_guest_asm`] call for interrupt delivery
/// without capturing anything: called by `lib.rs`'s `interrupt_signal_handler`
/// only when [`interrupted_pc_is_in_guest_entry_restore`] says `pc` is inside
/// [`enter_guest_asm`]'s own restore range, where the live [`PtRegs`] has not
/// been consumed by anything yet and so is still exactly the context the
/// guest would have resumed with -- see that function's own doc comment for
/// why no register capture is needed or correct here (capturing the
/// in-progress `mcontext` instead would hand the shim a mix of already-
/// restored guest registers and this platform's own still-live host state,
/// including a `pc` inside this platform's own binary).
///
/// # Safety
///
/// Must be called with `state` this thread's own live [`GuestThreadState`], its
/// `owns_cpu` genuinely true, and `pc` already confirmed inside
/// [`enter_guest_asm`]'s restore range, per the caller's own check.
pub(crate) unsafe fn abandon_guest_entry_for_interrupt(state: *mut GuestThreadState) -> usize {
    // SAFETY: the caller's precondition, as in `prepare_exception_delivery`.
    unsafe { (*state).owns_cpu.store(false, Ordering::Relaxed) };
    interrupt_callback as *const () as usize
}

/// Runs a guest thread with the given shim and initial context.
///
/// Allocates this thread's [`GuestThreadState`] on its own host stack and
/// publishes it in the reserved pthread TSD slot for the duration, calls
/// [`litebox::shim::EnterShim::init`], then loops: enter the guest, and
/// dispatch to [`litebox::shim::EnterShim::syscall`]/`exception`/`interrupt`
/// depending on why it returned, resuming until a handler returns
/// [`ContinueOperation::Terminate`].
///
/// Any number of threads may be inside this function at once; all the state the
/// switch keeps is per-thread and reached the `TPIDRRO_EL0` way (see this
/// module's own doc comment).
///
/// # Panics
///
/// Panics if this thread is *already* inside `run_thread` (a guest cannot host
/// a nested guest on the same thread; the inner one would overwrite the outer's
/// published state), or if the TSD slot cannot be reserved or written.
pub(crate) fn run_thread(
    shim: &dyn litebox::shim::EnterShim<ExecutionContext = PtRegs>,
    ctx: &mut PtRegs,
) {
    let key = reserve_guest_state_tsd_slot();
    assert!(
        current_guest_state().is_null(),
        "this thread is already running a guest; macOS guest entry is \
         per-thread but not reentrant (see litebox_platform_macos_userland::guest)"
    );

    // On this thread's own stack, so it lives exactly as long as this call and
    // costs no allocation on the guest-entry path.
    let mut state = GuestThreadState::new();
    let state = &raw mut state;

    // SAFETY: `key` was just reserved for this module's exclusive use, and
    // `state` addresses a live local that outlives the `defer` below (which
    // clears the slot before the frame goes away).
    let rc = unsafe { libc::pthread_setspecific(key, state.cast::<libc::c_void>()) };
    assert_eq!(
        rc, 0,
        "failed to publish this thread's guest-entry state: \
         pthread_setspecific returned {rc}"
    );
    let _clear = litebox::utils::defer(|| {
        // SAFETY: same live key; clearing it is what keeps a stale pointer to
        // this (about to be dead) stack frame from outliving the frame.
        unsafe { libc::pthread_setspecific(key, core::ptr::null()) };
    });

    if shim.init(ctx) == ContinueOperation::Terminate {
        return;
    }

    loop {
        // Enter/resume the guest. Returns after a guest syscall, a genuine
        // guest hardware fault, or a genuine guest interrupt, with `*ctx`
        // holding the guest state captured by the syscall callback,
        // `prepare_exception_delivery`, `prepare_interrupt_delivery` or
        // `abandon_guest_entry_for_interrupt` respectively.
        //
        // Logs the resume context (gated behind trace level, inert by
        // default; kept as a permanent debug aid alongside the `guest fault`
        // log below) so a captured post-fault `pc` of 0 (or any other bogus
        // value) can be checked against the `pc` litebox itself handed to
        // `enter_guest_asm` for this same entry -- distinguishing "litebox
        // resumed the guest at an already-corrupt PC" from "the guest was
        // handed a genuinely valid PC and corrupted it (or branched through a
        // corrupt register) during its own execution" without needing a
        // debugger attached. See the `macos-node-boot-null-pc` investigation
        // in `docs/roadmap.md`.
        //
        // SAFETY: `ctx` is a valid writable PtRegs, and `state` is this
        // thread's own live state, the one just published in its TSD slot.
        litebox_util_log::trace!(
            pc:? = ctx.pc, x16:? = ctx.regs[16], sp:? = ctx.sp;
            "about to resume guest"
        );
        let exit =
            GuestExit::from_asm_return(unsafe { enter_guest_asm(core::ptr::from_mut(ctx), state) });

        let op = match exit {
            GuestExit::Syscall => shim.syscall(ctx),
            GuestExit::Exception => {
                // SAFETY: `prepare_exception_delivery` filled this in just
                // before redirecting here, on this same thread.
                let info = unsafe { (*state).pending_exception_info };
                // Logs the full guest register state whenever a hardware fault
                // is delivered to the guest. Gated behind trace level
                // (`LITEBOX_LOG=litebox_platform_macos_userland=trace`), so it
                // is inert by default; kept as a permanent debug aid
                // (originally added for the
                // macos-concurrent-guest-entry-sigsegv investigation, see
                // `docs/roadmap.md`) since a guest fault's registers are
                // otherwise not observable without an attached debugger.
                //
                // It is emitted *here*, and deliberately not in
                // `prepare_exception_delivery` where it used to live, because
                // that function runs inside `lib.rs`'s `fault_handler` -- a
                // POSIX signal handler, where only async-signal-safe code may
                // run. Neither logging backend qualifies: measured on this
                // hardware with the real runner, `LITEBOX_LOG=...=trace` plus a
                // real guest fault reaches `tracing_core::event::Event::dispatch`
                // (and, on the first fault, `DefaultCallsite::register`) from
                // inside the handler, which takes the global callsite lock,
                // touches a `thread_local!` with a destructor, and reallocates
                // the subscriber's format buffer -- an interposed `realloc` was
                // observed being called with `SIGSEGV`+`SIGUSR2` still masked,
                // i.e. genuinely inside the handler.
                //
                // Moving it costs no information at all: `ctx` *is* the
                // `PtRegs` that `prepare_exception_delivery` filled in on this
                // thread (nothing between the handler's redirect and here
                // writes it), `info` is the `pending_exception_info` it
                // recorded in this thread's own `GuestThreadState`, and
                // `exception_callback` unconditionally returns into this loop,
                // so no fault that used to be logged goes unlogged.
                litebox_util_log::trace!(
                    regs:? = &ctx.regs, sp:? = ctx.sp, pc:? = ctx.pc,
                    fault_address:? = info.fault_address, esr:? = info.esr,
                    exception:? = info.exception;
                    "guest fault: captured register state"
                );
                shim.exception(ctx, &info)
            }
            GuestExit::Interrupt => {
                // Same reasoning as the exception arm above: this used to be
                // emitted from `prepare_interrupt_delivery`, which runs inside
                // `lib.rs`'s `interrupt_signal_handler`. Unlike the exception
                // arm, this also now covers the
                // `abandon_guest_entry_for_interrupt` case (an interrupt that
                // landed inside `enter_guest_asm`'s restore range, which
                // captures nothing because `*ctx` is already authoritative) --
                // previously invisible, and the register state it prints there
                // is exactly the context the guest would have resumed with.
                litebox_util_log::trace!(
                    regs:? = &ctx.regs, sp:? = ctx.sp, pc:? = ctx.pc;
                    "guest interrupt: captured register state"
                );
                shim.interrupt(ctx)
            }
        };
        if op == ContinueOperation::Terminate {
            return;
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use core::cell::RefCell;
    use litebox::shim::{EnterShim, Exception, ExceptionInfo};

    /// Shared between a spawned guest thread and the test driving it: the
    /// guest thread's own `pthread_t`, filled in from `EnterShim::init`
    /// (reached before any guest instruction runs) and a `Condvar` the driver
    /// waits on for it. Used by every test below that sends a real
    /// cross-thread `SIGUSR2`.
    type ReadySignal = std::sync::Arc<(
        std::sync::Mutex<Option<libc::pthread_t>>,
        std::sync::Condvar,
    )>;
    /// The `(regs, pc)` an interrupted guest's `EnterShim::interrupt` was
    /// called with, shared the same way [`ReadySignal`] is.
    type DeliveredInterrupt = std::sync::Arc<std::sync::Mutex<Option<([usize; 31], usize)>>>;

    /// Serializes the guest-entry tests against each other and against the
    /// tests elsewhere in this crate that do real host `mmap`/`munmap`
    /// (`allocate_jit_pages_hint_honors_the_suggested_address` and
    /// `with_signal_alt_stack_actually_registers_one` in `lib.rs`) -- those
    /// mutate the same real address space guest-entry tests do, and would
    /// otherwise race it. It is *not* a single-guest-thread lock any more:
    /// [`run_thread`] is per-thread now, and
    /// [`concurrent_guest_threads_each_keep_their_own_context`] deliberately
    /// runs several guests at once while holding this.
    pub(crate) static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Stands in for the word the rewriter's trampoline header holds and every
    /// real `SVC` gate loads its branch target from
    /// (`litebox_syscall_rewriter::arm64`'s `HEADER_CALLBACK_OFFSET`): the
    /// syscall entry point this process actually resolved, which is now a
    /// per-TSD-slot stub rather than one fixed function address. The
    /// hand-assembled guests below load through it exactly as a real gate does
    /// -- deliberately a `LDR` rather than the `ADRP`/`ADD` they used while the
    /// entry point was a plain symbol, because that is what the real emitted
    /// gate does.
    static TEST_SYSCALL_ENTRY: AtomicUsize = AtomicUsize::new(0);

    /// Publishes [`syscall_entry_point`] into [`TEST_SYSCALL_ENTRY`] so the
    /// hand-assembled guests below reach this process's own entry stub.
    /// Idempotent; every test that runs a guest calls it first.
    fn publish_test_syscall_entry() {
        TEST_SYSCALL_ENTRY.store(syscall_entry_point(), Ordering::Relaxed);
    }

    /// A stub shim that records the syscalls a guest makes. `write` (nr 64)
    /// returns its length and resumes; `exit` (nr 93) terminates.
    struct RecordingShim {
        seen: RefCell<Vec<(usize, usize, usize)>>, // (nr, x0, x1)
    }

    impl EnterShim for RecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let nr = ctx.regs[8];
            self.seen.borrow_mut().push((nr, ctx.regs[0], ctx.regs[1]));
            if nr == 93 {
                return ContinueOperation::Terminate;
            }
            // Emulate write(): return the byte count in x0, then resume.
            ctx.regs[0] = ctx.regs[2];
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A hand-assembled guest reproducing exactly what the rewriter emits: two
    /// syscalls whose `SVC`s have been replaced by the `SVC`-gate sequence
    /// (`emit_svc_gate` + shared handler) branching to this process's own
    /// [`syscall_entry_point`].
    /// `write(1, 0xABC, 7)` then `exit(42)`.
    #[unsafe(naked)]
    unsafe extern "C" fn test_guest() {
        core::arch::naked_asm!(
            // write(1, 0xABC, 7)
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xABC",
            "movz x2, #7",
            // SVC gate: save x16, record return address, jump to the callback.
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 20f@PAGE",
            "add  x16, x16, 20f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "20:", // resume point after the write syscall
            // exit(42)
            "movz x8, #93",
            "movz x0, #42",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 21f@PAGE",
            "add  x16, x16, 21f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "21:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    #[test]
    fn runs_a_guest_through_two_syscalls_and_exit() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: test_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let shim = RecordingShim {
            seen: RefCell::new(Vec::new()),
        };
        run_thread(&shim, &mut ctx);

        let seen = shim.seen.into_inner();
        assert_eq!(
            seen,
            vec![(64, 1, 0xABC), (93, 42, 0xABC)],
            "guest should have made write(1,0xABC,..) then exit(42)"
        );
    }

    /// The guest stack region [`syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp`]
    /// builds: a single valid page for the guest's usable stack, with an
    /// unmapped guard page immediately below it.
    struct GuardedStack {
        base: usize,
        page_size: usize,
    }

    impl GuardedStack {
        fn new() -> Self {
            // SAFETY: `sysconf` has no preconditions for this name.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }
                .try_into()
                .unwrap_or_else(|_| std::process::abort());
            // SAFETY: an anonymous mapping with no fixed-address request has no
            // precondition beyond what `mmap` itself checks.
            let base = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    page_size * 2,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANON,
                    -1,
                    0,
                )
            };
            assert_ne!(base, libc::MAP_FAILED, "failed to map the guarded stack");
            let base = base as usize;
            // SAFETY: `base` is the mapping just created, exactly `page_size`
            // bytes of which (the first page) this call alone will ever touch.
            let rc =
                unsafe { libc::mprotect(base as *mut libc::c_void, page_size, libc::PROT_NONE) };
            assert_eq!(rc, 0, "failed to guard the first page");
            Self { base, page_size }
        }

        /// The lowest address a guest occupying this stack may validly touch:
        /// the start of the second (mapped) page.
        fn valid_floor(&self) -> usize {
            self.base + self.page_size
        }
    }

    impl Drop for GuardedStack {
        fn drop(&mut self) {
            // SAFETY: `self.base` is this struct's own mapping, unmapped
            // exactly once here.
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.page_size * 2) };
        }
    }

    /// The *original* `syscall_callback` carved 288 bytes for its own `PtRegs`
    /// capture out of the guest's stack, below the 16 bytes the `SVC` gate
    /// itself needs -- so a guest stack with fewer than `16 + 288` valid bytes
    /// below `sp` would fault *inside host code*, not guest code (see
    /// `docs/roadmap.md`'s "A guest fault kills the host"). The fixed version
    /// captures directly into the host-owned live `PtRegs` and never
    /// dereferences anything below `sp - 16`, so a syscall must still complete
    /// cleanly with only those 16 bytes valid: this guest's `sp` sits with
    /// nothing but an unmapped guard page below that 16-byte floor. A build
    /// still carrying the original capture-on-the-guest-stack code would crash
    /// this whole test process with `SIGSEGV` instead of returning.
    #[test]
    fn syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();

        let stack = GuardedStack::new();
        let sp = stack.valid_floor() + 16;

        let mut ctx = PtRegs {
            pc: test_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = RecordingShim {
            seen: RefCell::new(Vec::new()),
        };
        run_thread(&shim, &mut ctx);

        let seen = shim.seen.into_inner();
        assert_eq!(
            seen,
            vec![(64, 1, 0xABC), (93, 42, 0xABC)],
            "guest should have made write(1,0xABC,..) then exit(42) even with a \
             guest stack that has only 16 valid bytes below sp"
        );
    }

    /// A shim that records a genuinely-delivered guest hardware fault: the
    /// [`ExceptionInfo`], the full captured register file, and the captured
    /// `pc` -- everything a naive "guest owns the CPU" check could instead
    /// fill with host state if it misattributed a host-side fault as the
    /// guest's own.
    struct FaultRecordingShim {
        reported_pc: core::cell::Cell<usize>,
        delivered: RefCell<Option<(ExceptionInfo, [usize; 31], usize)>>,
    }

    impl EnterShim for FaultRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            // The guest reports the address it is about to fault at (computed
            // with `adr`, immediately before the faulting instruction) via
            // write(1, that_address, 0).
            self.reported_pc.set(ctx.regs[1]);
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            *self.delivered.borrow_mut() = Some((*info, ctx.regs, ctx.pc));
            // There is no guest signal handler to resume into in this test.
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a caller-saved register (`x9`) and
    /// the link register (`x30`, singled out because a leaked host `x30` is
    /// exactly the return-to-host-code hazard this file exists to avoid),
    /// reports its own about-to-fault `pc` through a syscall, then genuinely
    /// faults by loading through a null pointer.
    #[unsafe(naked)]
    unsafe extern "C" fn faulting_guest() {
        core::arch::naked_asm!(
            "movz x9,  #0xCAFE",
            "movz x30, #0xBEEF",
            "movz x4,  #0",
            // write(1, &50f, 0): report the address about to fault.
            "movz x8, #64",
            "movz x0, #1",
            "adr  x1, 50f",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 50f@PAGE",
            "add  x16, x16, 50f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "50:",
            "ldr  x3, [x4]",  // deliberate fault: load through a null pointer
            "brk  #0",        // unreachable
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// The end-to-end fault-routing path this file exists to implement: a
    /// genuine guest hardware fault must reach [`EnterShim::exception`] with
    /// the guest's own state, and the host process must not die.
    #[test]
    fn delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        // Unlike the other tests in this module, this one deliberately faults,
        // so the platform's SIGSEGV/SIGBUS handler must actually be installed
        // -- production always does this via `MacOsUserland::new`, which this
        // test intentionally does not otherwise construct. Idempotent: safe to
        // call again if another test in this process already has.
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: faulting_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FaultRecordingShim {
            reported_pc: core::cell::Cell::new(0),
            delivered: RefCell::new(None),
        };
        // If this platform ever again misrouted a guest fault, this call
        // itself would take the whole test process down with a raw signal --
        // reaching the assertions below is already most of the proof.
        run_thread(&shim, &mut ctx);

        let reported_pc = shim.reported_pc.get();
        assert_ne!(reported_pc, 0, "guest never reported its expected fault pc");

        let (info, regs, pc) = shim
            .delivered
            .into_inner()
            .expect("EnterShim::exception was never invoked");

        assert_eq!(
            pc, reported_pc,
            "delivered pc must be exactly the guest's own faulting instruction \
             (self-reported via adr moments before faulting), never a host address"
        );
        assert_eq!(
            regs[9], 0xCAFE,
            "delivered x9 must be the guest's own sentinel, not host garbage"
        );
        assert_eq!(
            regs[30], 0xBEEF,
            "delivered x30 must be the guest's own sentinel, never a host return address"
        );
        assert_eq!(info.fault_address, 0, "guest dereferenced address 0");
        assert!(
            !info.kernel_mode,
            "this platform's guest never runs kernel-mode"
        );
        assert!(
            matches!(
                info.exception,
                Exception::DATA_ABORT_LOWER_EL | Exception::DATA_ABORT_CURRENT_EL
            ),
            "expected a data-abort exception class for a null-pointer load, got {:?}",
            info.exception
        );
    }

    /// The syscall number and first four arguments the gate reported.
    type RecordedSyscall = (i32, usize, usize, usize, usize);

    struct FaultedGateShim {
        syscall: core::cell::Cell<Option<RecordedSyscall>>,
        delivered: RefCell<Option<(ExceptionInfo, [usize; 31], usize)>>,
    }

    impl EnterShim for FaultedGateShim {
        type ExecutionContext = PtRegs;

        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }

        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            self.syscall.set(Some((
                ctx.syscallno,
                ctx.pc,
                ctx.sp,
                ctx.regs[16],
                ctx.regs[5],
            )));
            ctx.regs[0] = 123;
            ContinueOperation::Resume
        }

        fn exception(&self, ctx: &mut PtRegs, info: &ExceptionInfo) -> ContinueOperation {
            *self.delivered.borrow_mut() = Some((*info, ctx.regs, ctx.pc));
            ContinueOperation::Terminate
        }

        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    #[unsafe(naked)]
    unsafe extern "C" fn faulted_svc_gate_guest() {
        core::arch::naked_asm!(
            "movz x8, #172",
            "movz x16, #0xBEEF",
            "adr  x5, 50f",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 50f@PAGE",
            "add  x16, x16, 50f@PAGEOFF",
            "str  x16, [sp, #8]",
            "b    51f",
            "51:",
            "brk  #0",
            "50:",
            "movz x9, #0xCAFE",
            "movz x4, #0",
            "adr  x6, 60f",
            "60:",
            "ldr  x3, [x4]",
            "brk  #0",
        )
    }

    #[test]
    fn recovers_a_syscall_gate_fault_after_the_guest_stack_is_unmapped() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        let stack = GuardedStack::new();
        let sp = stack.valid_floor();
        let mut ctx = PtRegs {
            pc: faulted_svc_gate_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FaultedGateShim {
            syscall: core::cell::Cell::new(None),
            delivered: RefCell::new(None),
        };

        crate::with_signal_alt_stack(|| run_thread(&shim, &mut ctx));

        let (syscallno, pc, captured_sp, x16, reported_pc) = shim
            .syscall
            .get()
            .expect("the faulted gate did not dispatch a syscall");
        assert_eq!(syscallno, 172);
        assert_eq!(pc, reported_pc);
        assert_eq!(captured_sp, sp);
        assert_eq!(x16, 0xBEEF);

        let (info, regs, delivered_pc) = shim
            .delivered
            .into_inner()
            .expect("the post-syscall null fault was not delivered");
        assert_eq!(delivered_pc, regs[6]);
        assert_eq!(regs[9], 0xCAFE);
        assert_eq!(regs[16], 0xBEEF);
        assert_eq!(info.fault_address, 0);
    }

    /// A guest that faults without ever reading or writing through `sp`. `x5`
    /// self-reports the faulting PC so the test can distinguish the intended
    /// guest fault from a context-switch fault.
    #[unsafe(naked)]
    unsafe extern "C" fn stackless_faulting_guest() {
        core::arch::naked_asm!(
            "movz x9, #0xCAFE",
            "movz x4, #0",
            "adr  x5, 50f",
            "50:",
            "ldr  x3, [x4]", // deliberate fault: load through a null pointer
            "brk  #0",       // unreachable
        )
    }

    /// A corrupt guest `sp` must not be dereferenced by [`enter_guest_asm`].
    ///
    /// The context uses the first byte of a writable page as `sp`, with a
    /// `PROT_NONE` guard page immediately below it. The guest itself never uses
    /// `sp`; it deliberately faults through null instead. The former entry path
    /// wrote the guest PC to `sp - 8` and killed this entire host process before
    /// the guest could execute. The fixed path loads PC and x0 only from the
    /// host-owned `PtRegs`, reaches the guest, and reports its intended fault.
    #[test]
    fn entry_does_not_touch_memory_below_a_guest_sp() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        let stack = GuardedStack::new();
        let mut ctx = PtRegs {
            pc: stackless_faulting_guest as *const () as usize,
            sp: stack.valid_floor(),
            ..Default::default()
        };
        let shim = FaultRecordingShim {
            reported_pc: core::cell::Cell::new(0),
            delivered: RefCell::new(None),
        };

        crate::with_signal_alt_stack(|| run_thread(&shim, &mut ctx));

        let (info, regs, pc) = shim
            .delivered
            .into_inner()
            .expect("the guest's deliberate fault was not delivered");
        assert_eq!(pc, regs[5], "x5 must self-report the delivered guest PC");
        assert_eq!(regs[9], 0xCAFE, "guest register state must survive entry");
        assert_eq!(
            info.fault_address, 0,
            "the guest deliberately loaded from null"
        );
    }

    /// Same shape as [`faulting_guest`], but the deliberate fault is an
    /// *undefined instruction* rather than a bad load. The instruction is the
    /// real one this matters for: `sm3partw1 v4.4s, v0.4s, v3.4s`, encoding
    /// `0xce63c004`, which is what OpenSSL's `_armv8_sm3_probe` executes to
    /// discover whether the CPU implements FEAT_SM3. Apple Silicon does not, so
    /// it genuinely traps. Emitted as a raw `.inst` because the assembler will
    /// not accept the mnemonic without `+sm4` enabled, and enabling it here
    /// would say something untrue about the host.
    #[unsafe(naked)]
    unsafe extern "C" fn undefined_instruction_guest() {
        core::arch::naked_asm!(
            "movz x9,  #0xCAFE",
            "movz x30, #0xBEEF",
            // write(1, &50f, 0): report the address about to trap.
            "movz x8, #64",
            "movz x0, #1",
            "adr  x1, 50f",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 50f@PAGE",
            "add  x16, x16, 50f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "50:",
            ".inst 0xce63c004", // sm3partw1 v4.4s, v0.4s, v3.4s -- undefined here
            "brk  #0",          // unreachable
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// A guest that executes an undefined instruction must have it delivered to
    /// the guest, not kill the runner.
    ///
    /// Probing for an optional CPU feature by executing an instruction from it
    /// and catching the resulting `SIGILL` is a real, widespread idiom; Node's
    /// bundled OpenSSL does exactly this with `sm3partw1`. Before `SIGILL` was
    /// added to `install_fault_handlers`, that probe killed the whole runner
    /// process, because only `SIGSEGV`/`SIGBUS` were routed.
    ///
    /// The delivered exception class must be `UNKNOWN` (ESR EC 0), which is
    /// what an undefined instruction raises and what
    /// `litebox_shim_linux::syscalls::signal::aarch64::exception_signal`
    /// already turns into `Signal::SIGILL` -- so this platform-level routing was
    /// the only missing piece.
    #[test]
    fn delivers_an_undefined_instruction_to_the_shim_as_a_guest_exception() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: undefined_instruction_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FaultRecordingShim {
            reported_pc: core::cell::Cell::new(0),
            delivered: RefCell::new(None),
        };
        // Without the `SIGILL` handler this call takes the whole test process
        // down with a raw signal, so reaching the assertions is most of the
        // proof.
        run_thread(&shim, &mut ctx);

        let reported_pc = shim.reported_pc.get();
        assert_ne!(reported_pc, 0, "guest never reported its expected trap pc");

        let (info, regs, pc) = shim
            .delivered
            .into_inner()
            .expect("EnterShim::exception was never invoked for an undefined instruction");

        assert_eq!(
            pc, reported_pc,
            "delivered pc must be the guest's own undefined instruction, never a host address"
        );
        assert_eq!(
            regs[9], 0xCAFE,
            "delivered x9 must be the guest's own sentinel, not host garbage"
        );
        assert_eq!(
            regs[30], 0xBEEF,
            "delivered x30 must be the guest's own sentinel, never a host return address"
        );
        assert!(
            !info.kernel_mode,
            "this platform's guest never runs kernel-mode"
        );
        assert_eq!(
            info.exception,
            Exception::UNKNOWN,
            "an undefined instruction must arrive as ESR exception class 0 (UNKNOWN), \
             which is what the shim maps to SIGILL"
        );
    }

    /// Everything `lib.rs`'s `fault_handler` reaches runs inside a POSIX
    /// signal handler, so none of it may allocate: Darwin's allocator takes a
    /// non-reentrant `os_unfair_lock`, and a fault taken on a thread that was
    /// already inside `malloc` would deadlock the process rather than being
    /// delivered to the guest. This drives a *real* guest fault through the
    /// *real* handler with `crate::PROBE_ALLOCATOR` armed and
    /// requires the fault-delivery path to have allocated nothing while the
    /// handler's own signal mask was in force.
    ///
    /// Honest scope: this is a forward-looking guard, not a reproduction of
    /// the defect that motivated it. `prepare_exception_delivery` used to emit
    /// its `trace!` from inside the handler, which really does allocate --
    /// measured on the real runner, where `litebox_util_log`'s `tracing`
    /// backend is enabled -- but this crate's own test binary links the `log`
    /// backend with no logger installed, so `log::max_level()` is `Off` and
    /// the macro compiles down to a level check either way. What this test
    /// does lock in is that nothing on the handler path allocates
    /// *unconditionally*, which is what a future `format!`/`Vec`/`to_string`
    /// slipping into `fault_handler` or `prepare_exception_delivery` would do.
    ///
    /// The delivery assertion at the end is what keeps a pass from being
    /// vacuous: a zero count would otherwise also be satisfied by the handler
    /// never running at all.
    #[test]
    fn delivering_a_guest_fault_allocates_nothing_inside_the_signal_handler() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: faulting_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FaultRecordingShim {
            reported_pc: core::cell::Cell::new(0),
            delivered: RefCell::new(None),
        };

        crate::PROBE_ALLOCATOR.arm();
        run_thread(&shim, &mut ctx);
        let allocations_inside_handler = crate::PROBE_ALLOCATOR.disarm();

        assert!(
            shim.delivered.borrow().is_some(),
            "the guest fault was never delivered, so an allocation-free result \
             would prove nothing about the handler"
        );
        assert_eq!(
            allocations_inside_handler, 0,
            "the SIGSEGV/SIGBUS handler allocated on the host heap while \
             delivering a guest fault; every allocator call reachable from a \
             signal handler can deadlock against the thread it interrupted"
        );
    }

    /// A shim that captures the full register file at the first syscall and the
    /// first argument at the second, to check context-switch fidelity.
    struct FidelityShim {
        first: RefCell<Option<[usize; 31]>>,
        second_x1: core::cell::Cell<usize>,
        calls: core::cell::Cell<u32>,
    }

    impl EnterShim for FidelityShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let n = self.calls.get();
            self.calls.set(n + 1);
            match n {
                0 => {
                    *self.first.borrow_mut() = Some(ctx.regs);
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                1 => {
                    self.second_x1.set(ctx.regs[1]);
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                _ => ContinueOperation::Terminate,
            }
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a spread of callee- and caller-saved
    /// registers, makes a syscall (so the callback captures them), then -- after
    /// resuming -- passes the callee-saved `x19` sentinel as a syscall argument
    /// (so we can confirm it survived the enter/capture/resume round trip),
    /// then exits.
    #[unsafe(naked)]
    unsafe extern "C" fn fidelity_guest() {
        core::arch::naked_asm!(
            // Seed sentinels: x19 = 0x2222_1111 (callee-saved), x20/x28
            // (callee-saved), x9 (caller-saved).
            "movz x19, #0x1111",
            "movk x19, #0x2222, lsl #16",
            "movz x20, #0xBEEF",
            "movz x9,  #0xCAFE",
            "movz x28, #0xF00D",
            // syscall 1: write(1, 0xABC, 7)
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xABC",
            "movz x2, #7",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 30f@PAGE",
            "add  x16, x16, 30f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "30:",
            // syscall 2: write(2, x19, 0) -- x19 must still hold its sentinel.
            "movz x8, #64",
            "movz x0, #2",
            "mov  x1, x19",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 31f@PAGE",
            "add  x16, x16, 31f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "31:",
            // exit(0)
            "movz x8, #93",
            "movz x0, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 32f@PAGE",
            "add  x16, x16, 32f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "32:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// A guest that leaves a sentinel in `v8` and a non-default rounding mode in
    /// `FPCR` across a syscall, then reports both back through a second syscall.
    ///
    /// Linux preserves user FPSIMD across an `SVC`, so a real guest is entitled
    /// to do exactly this -- glibc's and musl's string routines hold live vector
    /// values across calls that may syscall.
    #[unsafe(naked)]
    unsafe extern "C" fn fp_fidelity_guest() {
        core::arch::naked_asm!(
            // v8 = 0x5555_4444, FPCR = round-toward-plus-infinity (RMode = 0b01).
            "movz x3, #0x4444",
            "movk x3, #0x5555, lsl #16",
            "fmov d8, x3",
            "movz x3, #0x40, lsl #16",
            "msr  fpcr, x3",
            // syscall 1: write(1, 0, 0) -- just a trip through the host.
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 40f@PAGE",
            "add  x16, x16, 40f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "40:",
            // syscall 2: write(2, v8_low, fpcr) -- both must have survived.
            "movz x8, #64",
            "movz x0, #2",
            "fmov x1, d8",
            "mrs  x2, fpcr",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 41f@PAGE",
            "add  x16, x16, 41f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "41:",
            // exit(0)
            "movz x8, #93",
            "movz x0, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 42f@PAGE",
            "add  x16, x16, 42f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "42:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// Scribble over the FP state a guest might be holding, the way ordinary
    /// host code does incidentally. Explicit here so the test proves the switch
    /// protects the guest rather than depending on whether this build's shim
    /// happened to touch a vector register.
    fn clobber_host_fp() {
        // SAFETY: writes only scratch FP state, all of it declared clobbered.
        unsafe {
            core::arch::asm!(
                "movi v8.16b, #0xFF",
                "msr  fpcr, xzr",
                out("v8") _,
                options(nostack),
            );
        }
    }

    /// The guest's FP/SIMD state must survive a syscall, because Linux's does.
    /// Before the switch saved it, the host's own use of the vector registers
    /// destroyed whatever the guest was holding.
    #[test]
    fn preserves_fp_state_across_capture_and_resume() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fp_fidelity_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FpFidelityShim {
            reported: core::cell::Cell::new(None),
            calls: core::cell::Cell::new(0),
        };
        run_thread(&shim, &mut ctx);

        let (v8_low, fpcr) = shim.reported.get().expect("second syscall not seen");
        assert_eq!(v8_low, 0x5555_4444, "v8 survived the round trip");
        assert_eq!(
            fpcr, 0x40_0000,
            "FPCR rounding mode survived the round trip"
        );
        assert_eq!(shim.calls.get(), 3, "expected write, write, exit");
    }

    struct FpFidelityShim {
        reported: core::cell::Cell<Option<(usize, usize)>>,
        calls: core::cell::Cell<u32>,
    }

    impl litebox::shim::EnterShim for FpFidelityShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let n = self.calls.get();
            self.calls.set(n + 1);
            // Stand in for the ordinary host code that runs between guest entries.
            clobber_host_fp();
            match n {
                0 => {
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                1 => {
                    self.reported.set(Some((ctx.regs[1], ctx.regs[2])));
                    ctx.regs[0] = 0;
                    ContinueOperation::Resume
                }
                _ => ContinueOperation::Terminate,
            }
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    #[test]
    fn preserves_registers_across_capture_and_resume() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fidelity_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FidelityShim {
            first: RefCell::new(None),
            second_x1: core::cell::Cell::new(0),
            calls: core::cell::Cell::new(0),
        };
        run_thread(&shim, &mut ctx);

        let first = shim.first.into_inner().expect("first syscall not seen");
        // Capture fidelity: every seeded register reached the callback intact.
        assert_eq!(first[19], 0x2222_1111, "x19 (callee-saved) captured");
        assert_eq!(first[20], 0xBEEF, "x20 (callee-saved) captured");
        assert_eq!(first[9], 0xCAFE, "x9 (caller-saved) captured");
        assert_eq!(first[28], 0xF00D, "x28 (callee-saved) captured");
        // Resume fidelity: x19 still held its sentinel after resuming, and the
        // guest passed it as the second syscall's x1.
        assert_eq!(
            shim.second_x1.get(),
            0x2222_1111,
            "x19 survived the enter/capture/resume round trip"
        );
        assert_eq!(shim.calls.get(), 3, "expected write, write, exit");
    }

    /// Pins the one host behavior that bounds how faithfully this platform can
    /// run a guest at all: XNU zeroes `x18` on every return to EL0, so no
    /// value the guest leaves in `x18` survives an arbitrary instruction
    /// boundary.
    ///
    /// [`enter_guest_asm`] and [`syscall_callback`] do save and restore guest
    /// `x18` (`ldp x18, x19, [x0, #144]` / `stp x18, x19, [x16, #144]`), so
    /// LiteBox's *own* guest-boundary crossings preserve it -- the sibling
    /// fidelity tests above cover that class of round trip. What no amount of
    /// save/restore can cover is the kernel's own crossings: a timer
    /// interrupt, a page fault, any exception at all taken while the guest is
    /// executing natively returns to EL0 with `x18` set to zero, and LiteBox
    /// is never notified. A guest whose compiler allocated `x18` as an
    /// ordinary general-purpose register therefore has it silently become
    /// `NULL` at a random point, at a rate proportional to the host's
    /// preemption rate.
    ///
    /// This is not hypothetical: it is the root cause of the intermittent
    /// concurrent-launch `SIGSEGV` tracked as
    /// `macos-concurrent-guest-entry-sigsegv` in `docs/roadmap.md`. Alpine's
    /// `ld-musl-aarch64.so.1` keeps `find_sym2`'s `name` argument in `x18`
    /// across its symbol search, so when the zeroing lands there the guest
    /// dereferences `NULL` in `gnu_lookup`'s name comparison.
    ///
    /// A syscall is used here because it is the one kernel entry a test can
    /// make happen on demand; the zeroing is a property of the *return to
    /// EL0*, not of syscalls specifically, which is why the asynchronous case
    /// above is the one that actually bites. If this test ever starts failing,
    /// Apple changed that behavior and the `x18` restriction documented on
    /// `litebox_syscall_rewriter::arm64::Host::MacOs` can be revisited.
    #[test]
    fn xnu_zeroes_guest_x18_on_every_return_to_el0() {
        const MAGIC: u64 = 0xABCD_1234_5678_EF01;
        // One kernel entry is enough to show the behavior; the repetition is
        // there to show it is unconditional rather than occasional.
        const ROUNDS: usize = 256;

        let mut observed = [MAGIC; ROUNDS];
        for slot in &mut observed {
            let after: u64;
            // SAFETY: `x18` is reserved by the Darwin AArch64 ABI, so no
            // compiler-generated code holds anything in it and writing it here
            // cannot disturb the caller. The `svc` is Darwin's `SYS_getpid`
            // (20), which takes no arguments, has no side effects, and clobbers
            // only the registers declared below plus the flags (`asm!` assumes
            // flags are clobbered by default).
            unsafe {
                core::arch::asm!(
                    "mov x18, {magic}",
                    "mov x16, #20",
                    "svc #0x80",
                    "mov {after}, x18",
                    magic = in(reg) MAGIC,
                    after = out(reg) after,
                    out("x0") _,
                    out("x1") _,
                    out("x16") _,
                    out("x17") _,
                    options(nostack),
                );
            }
            *slot = after;
        }

        assert!(
            observed.iter().all(|&v| v == 0),
            "expected XNU to zero x18 on every return to EL0, got {observed:?}"
        );
    }

    /// DIAGNOSTIC (not a permanent regression pin): the same proven-reliable
    /// SVC-based methodology as the test above, checking `x17` instead of
    /// `x18`. Darwin's raw `SVC` calling convention only reads `x16` (the
    /// syscall number) -- `x17` carries no meaning to the call itself, so
    /// unlike a `x16`-based probe this is not confounded by the ABI's own use
    /// of the register, the same way the test above is not confounded for
    /// `x18`.
    #[test]
    fn xnu_svc_x17_probe() {
        const MAGIC: u64 = 0xFEED_1700_FEED_1700;
        const ROUNDS: usize = 256;

        let mut observed = [MAGIC; ROUNDS];
        for slot in &mut observed {
            let after: u64;
            // SAFETY: same reasoning as the x18 test above; x17 here is pure
            // scratch, immediately overwritten by the guest and read back
            // right after the syscall returns.
            unsafe {
                core::arch::asm!(
                    "mov x17, {magic}",
                    "mov x16, #20",
                    "svc #0x80",
                    "mov {after}, x17",
                    magic = in(reg) MAGIC,
                    after = out(reg) after,
                    out("x0") _,
                    out("x1") _,
                    out("x16") _,
                    options(nostack),
                );
            }
            *slot = after;
        }

        // Unlike x18 (Apple's own reserved platform register, unconditionally
        // zeroed on every EL0 return -- see the test above), x17 has no
        // special significance to Darwin's own ABI or SVC calling convention
        // (only x16 carries the syscall number) and survives every round
        // trip. This is the direct, decisive evidence that XNU's x18-zeroing
        // does not generalize to "any register": it is specific to the one
        // register Apple's own ABI reserves, not a property every scratch
        // register shares. See docs/roadmap.md's "A further, distinct crash"
        // section for why this matters -- it refutes that section's leading
        // hypothesis that the further crash is the same XNU mechanism
        // hitting a different register.
        assert!(
            observed.iter().all(|&v| v == MAGIC),
            "expected x17 to survive every SVC (unlike x18), got {observed:?}"
        );
    }

    /// DIAGNOSTIC (not a permanent regression pin): tests `docs/roadmap.md`'s
    /// "A further, distinct crash" leading hypothesis -- that `X16` (the
    /// AArch64 ELF ABI's canonical PLT/lazy-binding scratch register) is
    /// corrupted the same way XNU's own ABI reserves and zeroes `x18`, but
    /// for a *real async signal* landing mid-execution rather than an `SVC`.
    /// Unlike the `x18`/`x17` probes above (both raw `SVC`s, which XNU's own
    /// ABI has a documented opinion about for `x16`/`x18` specifically as the
    /// syscall-number and platform registers), this probe holds a sentinel
    /// live in `x16` on a spinning thread with no `SVC` in flight at all, and
    /// interrupts it with a real cross-thread `SIGALRM` -- the exact
    /// mechanism `install_async_signal_handlers` installs for real guest
    /// preemption -- to see whether the delivered `mcontext.thread_state.x[16]`
    /// still holds the sentinel or reads corrupted, isolating XNU's own
    /// signal-delivery behavior from any litebox rewriter/gate machinery
    /// (neither the syscall rewriter nor `enter_guest_asm`'s own `X16` usage
    /// is anywhere in this test's call path).
    #[test]
    fn sigalrm_delivery_x16_probe() {
        use std::sync::atomic::{AtomicBool, AtomicU64};

        static CAPTURED_X16: AtomicU64 = AtomicU64::new(0);
        static CAPTURED: AtomicBool = AtomicBool::new(false);
        static SPIN: AtomicBool = AtomicBool::new(true);
        const SENTINEL: u64 = 0xABCD_1234_5678_EF16;

        extern "C" fn handler(
            _signum: libc::c_int,
            _info: *mut libc::siginfo_t,
            ucontext: *mut libc::c_void,
        ) {
            // SAFETY: the kernel hands a real `ucontext_t` to an
            // `SA_SIGINFO` handler; `uc_mcontext` points at a
            // `_STRUCT_MCONTEXT64` on this architecture, exactly as
            // `interrupt_signal_handler`/`fault_handler` assume.
            unsafe {
                let uc = ucontext.cast::<libc::ucontext_t>();
                if uc.is_null() {
                    return;
                }
                let mc = (*uc).uc_mcontext.cast::<crate::darwin::McontextPrefix64>();
                if mc.is_null() {
                    return;
                }
                let x16 = (*mc).thread_state.x[16];
                CAPTURED_X16.store(x16, Ordering::SeqCst);
                CAPTURED.store(true, Ordering::SeqCst);
                SPIN.store(false, Ordering::SeqCst);
            }
        }

        // Reset shared statics: this test may run alongside others in the
        // same process, but SIGALRM/this test's own statics are not touched
        // by anything else, so no serialization beyond the usual TEST_SERIAL
        // discipline (installing a process-wide signal handler) is needed
        // for correctness, only politeness -- take it anyway.
        let _guard = TEST_SERIAL.lock().unwrap();
        CAPTURED.store(false, Ordering::SeqCst);
        SPIN.store(true, Ordering::SeqCst);

        crate::darwin::install_handler(libc::SIGALRM, handler as *const () as usize, true, &[]);

        let tid = unsafe { libc::pthread_self() };
        let sender = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            // SAFETY: `tid` is a live pthread_t for the still-running spinner
            // below; pthread_kill with a signal this process has a handler
            // for is always safe to call.
            unsafe { libc::pthread_kill(tid, libc::SIGALRM) };
        });

        // Single asm block: load SENTINEL into x16 via immediates only (no
        // memory operand touches x16), then spin purely in asm on the flag's
        // address (staged in a different register) so x16 is never written
        // again by this thread's own code until read back at the very end --
        // the compiler cannot reallocate x16 mid-block since the whole
        // sequence is one inline-asm block, not separate Rust statements.
        let self_seen: u64;
        unsafe {
            core::arch::asm!(
                "movz x16, #0xef16",
                "movk x16, #0x5678, lsl #16",
                "movk x16, #0x1234, lsl #32",
                "movk x16, #0xabcd, lsl #48",
                "2:",
                "ldrb w9, [{flag}]",
                "cbnz w9, 2b",
                "mov {out}, x16",
                flag = in(reg) &raw const SPIN,
                out = out(reg) self_seen,
                out("x9") _,
                out("x16") _,
                options(nostack),
            );
        }

        sender.join().unwrap();
        crate::darwin::reraise_fatally(libc::SIGALRM);

        assert!(
            CAPTURED.load(Ordering::SeqCst),
            "SIGALRM handler never ran (test infrastructure issue, not a \
             finding about x16)"
        );
        let got = CAPTURED_X16.load(Ordering::SeqCst);
        assert_eq!(
            got, SENTINEL,
            "x16 corrupted by real SIGALRM delivery: mcontext held {got:#x}, \
             expected sentinel {SENTINEL:#x} (self-observed post-spin value \
             was {self_seen:#x}) -- this would confirm docs/roadmap.md's \
             leading hypothesis for the further, distinct crash"
        );
    }

    /// A shim that captures [`guest_fp_state`] the instant a fault is
    /// delivered -- the same accessor `lib.rs`'s `ThreadProvider::get_fp_state`
    /// exposes to the shim, so this is exactly what a real signal-frame build
    /// would see if it ran at this point.
    struct FpFaultShim {
        delivered: RefCell<Option<litebox::platform::FpSimdState64>>,
    }

    impl EnterShim for FpFaultShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            *self.delivered.borrow_mut() = Some(guest_fp_state());
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that broadcasts three distinct sentinel patterns into `v0`
    /// (first vector register), `v15` (middle), and `v31` (last) -- so a
    /// capture that silently only covered a subrange of the file would still
    /// be caught -- then genuinely faults through a null-pointer load, exactly
    /// like [`faulting_guest`]. `dup Vd.2d, Xn` broadcasts one sentinel into
    /// *both* 64-bit lanes of a register, which is what lets the test's
    /// expected value stay agnostic to which lane the capture code treats as
    /// low/high: both lanes are identical, so there is only one possible
    /// 128-bit result regardless.
    #[unsafe(naked)]
    unsafe extern "C" fn fp_faulting_guest() {
        core::arch::naked_asm!(
            "movz x9, #0xBEEF",
            "movk x9, #0xCAFE, lsl #16",
            "movk x9, #0xF00D, lsl #32",
            "movk x9, #0xFACE, lsl #48",
            "dup  v0.2d, x9",
            "movz x9, #0x1111",
            "movk x9, #0x2222, lsl #16",
            "movk x9, #0x3333, lsl #32",
            "movk x9, #0x4444, lsl #48",
            "dup  v15.2d, x9",
            "movz x9, #0xAAAA",
            "movk x9, #0xBBBB, lsl #16",
            "movk x9, #0xCCCC, lsl #32",
            "movk x9, #0xDDDD, lsl #48",
            "dup  v31.2d, x9",
            "movz x4, #0",
            "ldr  x3, [x4]", // deliberate fault: load through a null pointer
            "brk  #0",       // unreachable
        )
    }

    /// The Darwin-specific half of the FP/SIMD signal-frame gap this module's
    /// doc comment used to describe as open: a delivered exception's vector
    /// state must be the guest's own real state *at the moment of the fault*,
    /// read from the kernel's own `mcontext` (`darwin::ArmNeonState64`), not
    /// whatever the thread's saved `guest_fp` happened to hold from the guest's
    /// last syscall.
    /// If [`prepare_exception_delivery`] ever again skipped refreshing
    /// `guest_fp` from `neon_state`, this test would still pass by
    /// accident only if the guest's last syscall (there is none here) had
    /// coincidentally left the same sentinels -- it does not, so a regression
    /// here is a hard failure, not a flake.
    #[test]
    fn captures_real_vector_register_state_from_the_darwin_mcontext_on_a_guest_fault() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: fp_faulting_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = FpFaultShim {
            delivered: RefCell::new(None),
        };
        run_thread(&shim, &mut ctx);

        let fp = shim
            .delivered
            .into_inner()
            .expect("EnterShim::exception was never invoked");

        let expect_broadcast = |sentinel: u128| sentinel | (sentinel << 64);
        assert_eq!(
            fp.v[0],
            expect_broadcast(0xFACE_F00D_CAFE_BEEF),
            "v0 (first register) must be the guest's real pre-fault state"
        );
        assert_eq!(
            fp.v[15],
            expect_broadcast(0x4444_3333_2222_1111),
            "v15 (middle register) must be the guest's real pre-fault state"
        );
        assert_eq!(
            fp.v[31],
            expect_broadcast(0xDDDD_CCCC_BBBB_AAAA),
            "v31 (last register) must be the guest's real pre-fault state"
        );
    }

    /// A shim that records the syscall a guest reaches, to check what
    /// [`sigreturn_trampoline`] hands off to the run loop.
    struct SigreturnRecordingShim {
        seen: RefCell<Option<(i32, usize)>>, // (syscallno, sp)
    }

    impl EnterShim for SigreturnRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self.seen.borrow_mut() = Some((ctx.syscallno, ctx.sp));
            ContinueOperation::Terminate
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// A guest that branches straight into [`sigreturn_trampoline`] -- exactly
    /// what a real guest signal handler installed *without* `SA_RESTORER`
    /// does when it `ret`s, since `litebox_shim_linux`'s `write_signal_frame`
    /// installs this trampoline's address as `x30` in that case. A plain `B`
    /// (not `BL`) matches `RET`'s semantics: no return address is pushed,
    /// `SP` is left completely untouched, which is exactly the property the
    /// test below checks.
    #[unsafe(naked)]
    unsafe extern "C" fn returns_via_sigreturn_trampoline_guest() {
        core::arch::naked_asm!(
            "b {tramp}",
            tramp = sym sigreturn_trampoline,
        )
    }

    /// The no-`SA_RESTORER` half of the signal-delivery gap this module's doc
    /// comment used to describe as open: macOS has no vDSO to fall back to,
    /// so [`sigreturn_trampoline`] is LiteBox's own replacement -- reached the
    /// same way a real guest's `ret` from a handler would reach it, and
    /// proven here to hand off to `sys_rt_sigreturn`'s dispatch (syscall 139)
    /// with the guest's real, untouched `sp` -- never a guest-memory read (see
    /// the trampoline's own doc comment for why none of its other registers
    /// need to be captured for this specific syscall to dispatch correctly).
    /// If this ever crashed the host process instead of reaching
    /// `EnterShim::syscall`, this test would take the whole process down with
    /// it, the same proof-by-survival property
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// relies on.
    #[test]
    fn a_guest_signal_handler_without_sa_restorer_resumes_correctly_via_the_sigreturn_trampoline() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;

        let mut ctx = PtRegs {
            pc: returns_via_sigreturn_trampoline_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = SigreturnRecordingShim {
            seen: RefCell::new(None),
        };
        run_thread(&shim, &mut ctx);

        let (syscallno, reported_sp) = shim
            .seen
            .into_inner()
            .expect("EnterShim::syscall was never invoked");
        assert_eq!(
            syscallno,
            AARCH64_RT_SIGRETURN.cast_signed(),
            "trampoline must dispatch rt_sigreturn regardless of the guest's x8"
        );
        assert_eq!(
            reported_sp, sp,
            "trampoline must report the guest's real sp, unmoved by the \
             trampoline itself (RET touches no memory and no SP)"
        );
    }

    /// Pure logic, no guest involved: the two PC-range checks
    /// `lib.rs`'s `interrupt_signal_handler` relies on must agree with the
    /// addresses the labels they read actually resolve to, and the two
    /// ranges must not bleed into each other.
    #[test]
    fn interrupted_pc_range_checks_agree_with_the_known_switch_code_addresses() {
        let entry_restore_start = switch_to_guest_start as *const () as usize;
        let exit_syscall_start = syscall_callback_start as *const () as usize;
        let exit_sigreturn_start = sigreturn_trampoline_start as *const () as usize;
        // A small integer address is never a real code address any of this
        // platform's binary occupies.
        let unrelated = 1usize;

        assert!(
            interrupted_pc_is_in_guest_entry_restore(entry_restore_start),
            "the labelled start of enter_guest_asm's own restore range must \
             read as inside it"
        );
        assert!(
            !interrupted_pc_is_in_guest_entry_restore(unrelated),
            "an address with nothing to do with guest entry must read as \
             outside the restore range"
        );
        assert!(
            interrupted_pc_is_in_guest_exit_prologue(exit_syscall_start),
            "syscall_callback's own start must read as inside the \
             exit-prologue range"
        );
        assert!(
            interrupted_pc_is_in_guest_exit_prologue(exit_sigreturn_start),
            "sigreturn_trampoline's own start must read as inside the \
             exit-prologue range"
        );
        assert!(
            !interrupted_pc_is_in_guest_exit_prologue(unrelated),
            "an address with nothing to do with either exit path must read \
             as outside the exit-prologue range"
        );
        assert!(
            !interrupted_pc_is_in_guest_entry_restore(exit_syscall_start),
            "the two ranges must not overlap: syscall_callback's start is not \
             inside enter_guest_asm's restore range"
        );
        assert!(
            !interrupted_pc_is_in_guest_exit_prologue(entry_restore_start),
            "the two ranges must not overlap: enter_guest_asm's restore start \
             is not inside syscall_callback's/sigreturn_trampoline's range"
        );
    }

    /// A shim that records a genuinely-delivered guest interrupt: the full
    /// captured register file and `pc` -- everything a naive "guest owns the
    /// CPU" check could instead fill with host state if it misattributed the
    /// moment `SIGUSR2` arrived, the same disclosure-class concern
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// already established for the fault path. `ready` hands the real guest
    /// thread's `pthread_t` back to the test as soon as it is known (from
    /// [`EnterShim::init`], reached before any guest instruction runs), so the
    /// test can target the real interrupt-delivery mechanism
    /// (`libc::pthread_kill`) exactly as `ThreadProvider::interrupt_thread`
    /// does, rather than a substitute.
    struct InterruptRecordingShim {
        ready: ReadySignal,
        delivered: DeliveredInterrupt,
    }

    impl EnterShim for InterruptRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            // SAFETY: `pthread_self` has no preconditions.
            let self_id = unsafe { libc::pthread_self() };
            let (lock, cvar) = &*self.ready;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self_id);
            cvar.notify_one();
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self
                .delivered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((ctx.regs, ctx.pc));
            ContinueOperation::Terminate
        }
    }

    /// A guest that seeds sentinels into a caller-saved register (`x9`) and
    /// the link register (`x30`, singled out because a leaked host `x30` is
    /// exactly the return-to-host-code hazard this file exists to avoid,
    /// mirroring `faulting_guest`'s identical check for the fault path),
    /// reports it is about to start via a syscall, then spins in a large but
    /// bounded counting loop. Bounded, not infinite: a build that regressed
    /// interrupt delivery fails this test loudly (via the guest's own
    /// `exit(99)` below, observed as `EnterShim::interrupt` never firing)
    /// instead of hanging the whole suite.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_spin_guest() {
        core::arch::naked_asm!(
            "movz x9,  #0xCAFE",
            "movz x30, #0xBEEF",
            // write(1, 0, 0): just a trip through the host so the test knows
            // (via EnterShim::init, already reached by this point) that the
            // guest thread exists, and (once this syscall itself completes)
            // that it is about to enter the spin loop below.
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 70f@PAGE",
            "add  x16, x16, 70f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "70:",
            // ~400 million iterations: comfortably longer (by roughly an
            // order of magnitude on this hardware) than the delay the test
            // waits after the syscall above before sending SIGUSR2, so the
            // signal lands squarely inside this loop (genuinely executing
            // guest code) rather than racing the syscall_callback exit-
            // prologue window this test does not target. Still finite.
            "movz x5, #0x8400",
            "movk x5, #0x17D7, lsl #16",
            "71:",
            "subs x5, x5, #1",
            "bne  71b",
            // Only reached if the interrupt was never delivered in time.
            "movz x8, #93",
            "movz x0, #99",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 72f@PAGE",
            "add  x16, x16, 72f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "72:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// The end-to-end interrupt-routing path this row exists to implement: a
    /// genuine `SIGUSR2` delivered while the guest is truly executing (not
    /// mid-switch) must reach [`EnterShim::interrupt`] with the guest's own
    /// state, on real hardware, via the real `libc::pthread_kill` delivery
    /// mechanism -- not a substitute.
    #[test]
    fn delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();
        // No pending-interrupt reset is needed (there used to be one here):
        // `GuestThreadState::pending_interrupt` is per-thread and created
        // fresh by every `run_thread` call, so a stray `SIGUSR2` that landed
        // on some other thread in an earlier test cannot leak into this
        // guest's own state the way the old process-global flag could.

        let ready = std::sync::Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let delivered = std::sync::Arc::new(std::sync::Mutex::new(None));
        let shim = InterruptRecordingShim {
            ready: std::sync::Arc::clone(&ready),
            delivered: std::sync::Arc::clone(&delivered),
        };

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_spin_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let guest_thread = std::thread::Builder::new()
            .spawn(move || {
                // SAFETY: `ctx` describes a runnable guest context with >= 16
                // valid bytes below `sp`; `TEST_SERIAL` (held by the caller
                // for this whole test) enforces the single-guest-thread
                // invariant this crate's guest-entry state relies on.
                unsafe { crate::run_thread(shim, &mut ctx) };
            })
            .expect("failed to spawn the guest thread");

        let (lock, cvar) = &*ready;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, timeout) = cvar
            .wait_timeout_while(guard, std::time::Duration::from_secs(5), |id| id.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "guest thread never reported ready within 5s"
        );
        let guest_tid = guard.expect("condition guarantees Some once not timed out");
        drop(guard);

        // Give the guest a generous head start into its spin loop -- orders
        // of magnitude past enter_guest_asm's own restore window (tens of
        // nanoseconds) and well short of the ~400M-iteration loop's own
        // duration, so the signal below lands in genuine guest execution.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // SAFETY: `guest_tid` is the live guest thread's own id, captured
        // moments ago; it cannot have exited yet (its only exit path is the
        // ~100ms-away exit(99) fallback).
        let rc = unsafe { libc::pthread_kill(guest_tid, libc::SIGUSR2) };
        assert_eq!(rc, 0, "pthread_kill(SIGUSR2) failed with errno {rc}");

        guest_thread.join().expect("guest thread panicked");

        let (regs, pc) = delivered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect(
                "EnterShim::interrupt was never invoked -- SIGUSR2 delivery \
                 regressed (the guest fell through to its own exit(99))",
            );

        assert_eq!(
            regs[9], 0xCAFE,
            "delivered x9 must be the guest's own sentinel, not host garbage"
        );
        assert_eq!(
            regs[30], 0xBEEF,
            "delivered x30 must be the guest's own sentinel, never a host \
             return address"
        );
        let spin_start = interrupt_spin_guest as *const () as usize;
        assert!(
            (spin_start..spin_start + 0x200).contains(&pc),
            "delivered pc ({pc:#x}) must be inside the guest's own spin loop \
             ({spin_start:#x}..), never a host address"
        );
    }

    /// A shim whose `syscall` handler synchronously self-signals with
    /// `SIGUSR2` the moment it observes the guest's first syscall (marker
    /// `0xAAAA` in `x1`) -- at that exact instant `owns_cpu` genuinely
    /// reads false (ordinary Rust host code, well past the syscall callback's
    /// own clear), so this deterministically exercises
    /// `interrupt_signal_handler`'s case 1 and `pending_interrupt`'s
    /// re-check in [`enter_guest_asm`], rather than racing real concurrent
    /// timing the way
    /// [`delivers_a_genuine_guest_interrupt_to_the_shim_without_leaking_host_state`]
    /// does for the genuinely-executing case.
    struct PendingInterruptRecheckShim {
        syscall_markers: std::sync::Mutex<Vec<usize>>,
        interrupted_ctx: std::sync::Mutex<Option<(usize, usize, i32)>>,
    }

    impl EnterShim for PendingInterruptRecheckShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            self.syscall_markers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ctx.regs[1]);
            if ctx.regs[1] == 0xAAAA {
                // SAFETY: `raise` has no preconditions beyond a valid signal
                // number; `SIGUSR2` is not blocked on this thread outside
                // another handler's own execution (see
                // `darwin::install_handler`'s doc comment for the two
                // handlers this *is* masked against, neither of which is
                // running here), so this is delivered synchronously, before
                // `raise` returns, exactly as a real cross-thread
                // `pthread_kill` arriving in this same narrow window would be
                // -- this test just makes the race deterministic instead of
                // leaving it to timing.
                unsafe { libc::raise(libc::SIGUSR2) };
            }
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            ContinueOperation::Terminate
        }
        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            *self
                .interrupted_ctx
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some((ctx.pc, ctx.sp, ctx.syscallno));
            ContinueOperation::Terminate
        }
    }

    /// A guest that makes one syscall (marker `0xAAAA`), then -- only if it
    /// ever genuinely resumes, which a correct `pending_interrupt` re-check
    /// must prevent -- makes a second, distinctly-marked syscall (`0xBBBB`)
    /// so the test can detect and fail on that instead of silently
    /// mismatching.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_pending_recheck_guest() {
        core::arch::naked_asm!(
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xAAAA",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 73f@PAGE",
            "add  x16, x16, 73f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "73:",
            "movz x8, #64",
            "movz x0, #1",
            "movz x1, #0xBBBB",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 74f@PAGE",
            "add  x16, x16, 74f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "74:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
        )
    }

    /// Piece 4 of this row's design (see `GuestThreadState::pending_interrupt`'s doc
    /// comment): an interrupt that cannot be redirected immediately (here,
    /// because it arrives while genuinely between guest entries) must not be
    /// silently dropped -- it has to be honored the next time
    /// [`enter_guest_asm`] is about to hand control back to the guest,
    /// *before* the guest executes another instruction. Deterministic (no
    /// real concurrency, no timing dependency): the self-signal in
    /// [`PendingInterruptRecheckShim::syscall`] is synchronous.
    #[test]
    fn an_interrupt_racing_a_fresh_guest_entry_is_honored_before_any_further_guest_instruction_runs()
     {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_pending_recheck_guest as *const () as usize,
            sp,
            ..Default::default()
        };
        let shim = PendingInterruptRecheckShim {
            syscall_markers: std::sync::Mutex::new(Vec::new()),
            interrupted_ctx: std::sync::Mutex::new(None),
        };

        // `SIGUSR2` here is only ever `raise()`d synchronously from host Rust
        // code inside `PendingInterruptRecheckShim::syscall` (never async,
        // never while the host is on the guest's own stack), so this test
        // does not need `with_signal_alt_stack`/`crate::run_thread`'s full
        // wrapping the way the genuinely-concurrent test above does; the
        // module-local `run_thread` (taking `&dyn EnterShim`, not consuming
        // `shim`) lets this test read `shim`'s fields back afterward.
        run_thread(&shim, &mut ctx);

        let markers = shim
            .syscall_markers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(
            *markers,
            vec![0xAAAA],
            "the guest must never reach its second syscall (0xBBBB) -- \
             pending_interrupt must redirect to EnterShim::interrupt before \
             any guest instruction after the first syscall runs"
        );
        drop(markers);

        let (pc, interrupted_sp, syscallno) = shim
            .interrupted_ctx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .expect("EnterShim::interrupt was never invoked");
        assert_eq!(
            pc, ctx.pc,
            "the interrupted ctx must be exactly what the first syscall's \
             handler left it as -- nothing captured or overwritten it"
        );
        assert_eq!(interrupted_sp, sp, "sp must be unchanged from the syscall");
        assert_eq!(
            syscallno, 64,
            "syscallno must still be the first syscall's own (write), not \
             clobbered by an aborted second entry"
        );
    }

    /// How many round trips [`interrupt_stress_guest`] makes; large enough to
    /// give a concurrent `SIGUSR2` hammer many thousands of chances to land
    /// inside every one of `enter_guest_asm`'s/`syscall_callback`'s/
    /// `sigreturn_trampoline`'s ownership-boundary windows over the life of
    /// one test run, small enough that the test still finishes quickly.
    const STRESS_ITERATIONS: u16 = 4000;

    /// A shim that records the full syscall trace and exit code of
    /// [`interrupt_stress_guest`], plus how many times
    /// [`EnterShim::interrupt`] actually fired -- shared via `Arc`/`Mutex`
    /// rather than the plain `RefCell`/`Cell` the rest of this module's shims
    /// use, because this one is moved into a spawned thread by
    /// [`crate::run_thread`] (which takes its shim by value and never hands
    /// it back) while the test still needs to read the results afterward.
    struct StressRecordingShim {
        ready: ReadySignal,
        hammer_live: HammerLive,
        seen: std::sync::Arc<std::sync::Mutex<Vec<usize>>>,
        exit_code: std::sync::Arc<std::sync::Mutex<Option<usize>>>,
        interrupts_seen: std::sync::Arc<std::sync::atomic::AtomicU32>,
    }

    /// Set by the hammer thread once it has actually issued its first
    /// `pthread_kill`, and waited for by [`StressRecordingShim::init`] before
    /// it lets the guest run a single instruction.
    ///
    /// Without this handshake the test was genuinely racy in a way that made it
    /// silently stop testing what it claims: the guest's 4000 round trips take
    /// well under a millisecond, so on an unlucky schedule the hammer thread
    /// had not been dispatched at all before the guest finished, and
    /// `interrupts_seen` came back `0`. Measured on this hardware, at the
    /// commit before this one, that happened on 2 of 15 idle runs and 3 of 15
    /// runs under load -- a pre-existing flake in the final assertion, not a
    /// property of what is being tested. The wait strengthens the test (it can
    /// no longer pass while exercising nothing) rather than relaxing it: the
    /// `interrupts_seen > 0` assertion below is unchanged.
    type HammerLive = std::sync::Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

    impl EnterShim for StressRecordingShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            // SAFETY: `pthread_self` has no preconditions.
            let self_id = unsafe { libc::pthread_self() };
            let (lock, cvar) = &*self.ready;
            *lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self_id);
            cvar.notify_one();

            // Hold the guest here until the hammer is genuinely running. This
            // thread's `GuestThreadState` is already published by `run_thread`
            // at this point (publication happens before `EnterShim::init`), so
            // a `SIGUSR2` arriving during this wait is recorded as pending and
            // honored by the very first `enter_guest_asm` -- which is exactly
            // the delivery path the assertion at the end of this test is about.
            let (lock, cvar) = &*self.hammer_live;
            let guard = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let (_guard, timeout) = cvar
                .wait_timeout_while(guard, std::time::Duration::from_secs(5), |live| !*live)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                !timeout.timed_out(),
                "the hammer thread never reported live within 5s"
            );
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            if ctx.regs[8] == 93 {
                *self
                    .exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ctx.regs[0]);
                return ContinueOperation::Terminate;
            }
            self.seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ctx.regs[1]);
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            // A real exception here would mean a fault got misattributed as
            // this guest's own -- it never touches memory beyond its own
            // stack slots -- so terminating (rather than trying to recover)
            // is deliberate: the test's assertions on `seen`/`exit_code`
            // catch the resulting desync.
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            self.interrupts_seen.fetch_add(1, Ordering::Relaxed);
            ContinueOperation::Resume
        }
    }

    /// A guest that performs [`STRESS_ITERATIONS`] syscalls in a tight loop,
    /// each carrying its own loop index in `x1` (so the test can verify the
    /// full sequence landed exactly once, in order), then exits with a
    /// distinctive code.
    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_stress_guest() {
        core::arch::naked_asm!(
            "movz x19, #0", // loop counter -- callee-saved, survives each round trip
            "75:",
            "movz x8, #64",
            "movz x0, #1",
            "mov  x1, x19",
            "movz x2, #0",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 76f@PAGE",
            "add  x16, x16, 76f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "76:",
            "add  x19, x19, #1",
            "cmp  x19, #{iters}",
            "bne  75b",
            "movz x8, #93",
            "movz x0, #55",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 77f@PAGE",
            "add  x16, x16, 77f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "77:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
            iters = const STRESS_ITERATIONS,
        )
    }

    /// Defense-in-depth, proof-by-survival (the same property
    /// [`delivers_a_genuine_guest_fault_to_the_shim_without_leaking_host_state`]
    /// relies on): a concurrent thread hammers real `SIGUSR2` at the guest
    /// thread throughout its whole run, landing at essentially random points
    /// across thousands of `enter_guest_asm`/`syscall_callback` round trips --
    /// including, over enough iterations, the narrow entry-restore and
    /// exit-prologue windows the two deterministic tests above exercise one
    /// at a time. A misattribution here would either desynchronize the
    /// asserted trace/exit-code below or crash the process outright; this
    /// test does not attempt to prove any *specific* interrupt landed in any
    /// *specific* window (unlike the two deterministic tests above), only
    /// that heavy, realistic concurrent pressure never corrupts the syscall
    /// stream.
    #[test]
    fn concurrent_sigusr2_delivery_does_not_corrupt_a_running_syscall_stream() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();
        crate::install_async_signal_handlers();

        let ready = std::sync::Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let exit_code = std::sync::Arc::new(std::sync::Mutex::new(None));
        let interrupts_seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let hammer_live: HammerLive =
            std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let shim = StressRecordingShim {
            ready: std::sync::Arc::clone(&ready),
            hammer_live: std::sync::Arc::clone(&hammer_live),
            seen: std::sync::Arc::clone(&seen),
            exit_code: std::sync::Arc::clone(&exit_code),
            interrupts_seen: std::sync::Arc::clone(&interrupts_seen),
        };

        let mut stack = vec![0u8; 1 << 16];
        let top = stack.as_mut_ptr() as usize + stack.len();
        let sp = (top - 256) & !15;
        let mut ctx = PtRegs {
            pc: interrupt_stress_guest as *const () as usize,
            sp,
            ..Default::default()
        };

        let guest_thread = std::thread::Builder::new()
            .spawn(move || {
                // SAFETY: `ctx` describes a runnable guest context with >= 16
                // valid bytes below `sp`; `TEST_SERIAL` enforces the single-
                // guest-thread invariant for the duration of this test.
                unsafe { crate::run_thread(shim, &mut ctx) };
            })
            .expect("failed to spawn the guest thread");

        let (lock, cvar) = &*ready;
        let guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (guard, timeout) = cvar
            .wait_timeout_while(guard, std::time::Duration::from_secs(5), |id| id.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !timeout.timed_out(),
            "guest thread never reported ready within 5s"
        );
        let guest_tid = guard.expect("condition guarantees Some once not timed out");
        drop(guard);

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hammer_stop = std::sync::Arc::clone(&stop);
        let hammer_ready = std::sync::Arc::clone(&hammer_live);
        let hammer = std::thread::Builder::new()
            .spawn(move || {
                // SAFETY: `guest_tid` was captured from a live thread above and
                // is only ever signalled while that thread (or its exit race,
                // harmless for `pthread_kill`) is still within this test's
                // scope. The guest is parked in `EnterShim::init` until the
                // handshake below, so this first delivery cannot be missed.
                unsafe { libc::pthread_kill(guest_tid, libc::SIGUSR2) };
                let (lock, cvar) = &*hammer_ready;
                *lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                cvar.notify_one();

                while !hammer_stop.load(Ordering::Relaxed) {
                    // SAFETY: as above.
                    unsafe { libc::pthread_kill(guest_tid, libc::SIGUSR2) };
                }
            })
            .expect("failed to spawn the hammer thread");

        guest_thread.join().expect("guest thread panicked");
        stop.store(true, Ordering::Relaxed);
        hammer.join().expect("hammer thread panicked");
        // The hammer thread's own last `pthread_kill` call races the guest
        // thread's exit with no way to fully close that window from here (it
        // may land after the guest thread has already exited, on whatever
        // unrelated thread the OS has since reused that `pthread_t` for). That
        // used to need an explicit process-global reset here, because the
        // stray delivery would set the shared `PENDING_INTERRUPT` and the next
        // guest-entry test would consume it (found by a real failure of
        // `syscall_survives_a_guest_stack_with_only_16_valid_bytes_below_sp`).
        // With per-thread state there is nothing left to reset: the stray
        // signal lands on a thread whose `GuestThreadState` is either gone or
        // was never published, and `record_pending_interrupt` drops it.

        let seen = std::mem::take(
            &mut *seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let expected: Vec<usize> = (0..usize::from(STRESS_ITERATIONS)).collect();
        assert_eq!(
            seen, expected,
            "the full syscall trace must land exactly once, in order, \
             despite continuous concurrent SIGUSR2 pressure"
        );
        assert_eq!(
            *exit_code
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(55),
            "the guest must reach its own real exit, not a fault/misrouted \
             path"
        );
        // Not a strict correctness requirement -- resend timing is not
        // controlled -- but a run that never once actually reached
        // EnterShim::interrupt across this many round trips under continuous
        // hammering would mean this test is not exercising the path it
        // claims to; observed in practice to land in the thousands on this
        // hardware.
        assert!(
            interrupts_seen.load(Ordering::Relaxed) > 0,
            "expected at least one real interrupt delivery under continuous \
             concurrent SIGUSR2 pressure across {STRESS_ITERATIONS} round trips"
        );
    }

    /// A guest that opens its own 64-byte stack frame *between* one syscall's
    /// resume point and the next syscall -- exactly what a compiled function
    /// does before calling a library routine that issues one -- and reads a
    /// value back out of that frame each time round.
    ///
    /// This shape is the whole reason the per-thread state is reached through
    /// `TPIDRRO_EL0` rather than staged below the guest `SP` at resume time:
    /// the staged-word design passed every other test in this module and then
    /// `SIGSEGV`ed on precisely this guest, because the staged pointer's
    /// address is relative to `SP` *as of the resume*, and this guest's `SP`
    /// has moved by the time its next `SVC` gate runs (see `docs/roadmap.md`).
    ///
    /// On entry `x0` carries a sentinel (from `ctx.regs[0]`), which the guest
    /// keeps in the callee-saved `x19` and in `v0` for the whole run and
    /// re-reports every iteration, so a context that got crossed with another
    /// thread's shows up as a wrong reported value rather than only as a crash.
    #[unsafe(naked)]
    unsafe extern "C" fn sp_shifting_guest() {
        core::arch::naked_asm!(
            "mov  x19, x0",             // callee-saved sentinel
            "dup  v0.2d, x19",          // ... and a vector-register copy of it
            "mov  x20, #0",             // iteration counter
            "60:",
            // Open a real stack frame *after* the previous resume and *before*
            // the next syscall: the guest's SP at the SVC gate is now 64 bytes
            // below where it was when enter_guest_asm handed control back.
            "sub  sp, sp, #64",
            "str  x19, [sp, #24]",
            "movz x8, #64",
            "movz x0, #1",
            "ldr  x1, [sp, #24]",       // sentinel, via this guest's own frame
            "mov  x2, x20",             // iteration
            "fmov x3, d0",              // sentinel, via the vector file
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 61f@PAGE",
            "add  x16, x16, 61f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "61:",
            "add  sp, sp, #64",
            "add  x20, x20, #1",
            "movz x4, #{iters}",
            "cmp  x20, x4",
            "b.lt 60b",
            // exit(sentinel)
            "movz x8, #93",
            "mov  x0, x19",
            "sub  sp, sp, #16",
            "str  x16, [sp]",
            "adrp x16, 62f@PAGE",
            "add  x16, x16, 62f@PAGEOFF",
            "str  x16, [sp, #8]",
            "adrp x16, {cb}@PAGE",
            "add  x16, x16, {cb}@PAGEOFF",
            "ldr  x16, [x16]",
            "br   x16",
            "62:",
            "brk  #0",
            cb = sym TEST_SYSCALL_ENTRY,
            iters = const SP_SHIFT_ITERATIONS,
        )
    }

    /// Round trips [`sp_shifting_guest`] makes. Enough that a wrong-address
    /// dereference has many chances to land on an unmapped page, few enough to
    /// stay instant.
    const SP_SHIFT_ITERATIONS: u16 = 256;

    /// Everything one run of [`sp_shifting_guest`] reported, shared by `Arc`
    /// because [`crate::run_thread`] takes its shim by value and never gives it
    /// back.
    #[derive(Default)]
    struct SpShiftReport {
        /// `(sentinel via the stack frame, iteration, sentinel via `v0`)`.
        seen: std::sync::Mutex<Vec<(usize, usize, usize)>>,
        exit_code: std::sync::Mutex<Option<usize>>,
    }

    struct SpShiftShim {
        report: std::sync::Arc<SpShiftReport>,
    }

    impl EnterShim for SpShiftShim {
        type ExecutionContext = PtRegs;
        fn init(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            if ctx.regs[8] == 93 {
                *self
                    .report
                    .exit_code
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ctx.regs[0]);
                return ContinueOperation::Terminate;
            }
            self.report
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((ctx.regs[1], ctx.regs[2], ctx.regs[3]));
            ctx.regs[0] = 0;
            ContinueOperation::Resume
        }
        fn exception(&self, _ctx: &mut PtRegs, _info: &ExceptionInfo) -> ContinueOperation {
            // This guest touches nothing but its own stack, so a delivered
            // exception means the switch dereferenced something it should not
            // have; terminating makes the assertions below fail loudly.
            ContinueOperation::Terminate
        }
        fn interrupt(&self, _ctx: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Terminate
        }
    }

    /// Runs [`sp_shifting_guest`] with `sentinel` on a fresh host thread,
    /// through the production [`crate::run_thread`] wrapper (alternate signal
    /// stack and thread handle included), and returns what it reported.
    fn run_sp_shifting_guest(sentinel: usize) -> std::thread::JoinHandle<SpShiftReport> {
        std::thread::Builder::new()
            .spawn(move || {
                let report = std::sync::Arc::new(SpShiftReport::default());
                let shim = SpShiftShim {
                    report: std::sync::Arc::clone(&report),
                };
                let mut stack = vec![0u8; 1 << 16];
                let top = stack.as_mut_ptr() as usize + stack.len();
                let sp = (top - 4096) & !15;
                let mut ctx = PtRegs {
                    pc: sp_shifting_guest as *const () as usize,
                    sp,
                    ..Default::default()
                };
                ctx.regs[0] = sentinel;
                // SAFETY: `ctx` describes a runnable guest context with a real
                // stack and ample room below `sp`.
                unsafe { crate::run_thread(shim, &mut ctx) };
                drop(stack);
                std::sync::Arc::into_inner(report).expect("the guest thread holds the last ref")
            })
            .expect("failed to spawn the guest thread")
    }

    /// Checks one [`sp_shifting_guest`] run reported exactly its own sentinel,
    /// every iteration, in order, and exited with it.
    fn assert_sp_shift_report(report: &SpShiftReport, sentinel: usize) {
        let seen = std::mem::take(
            &mut *report
                .seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let expected: Vec<(usize, usize, usize)> = (0..usize::from(SP_SHIFT_ITERATIONS))
            .map(|i| (sentinel, i, sentinel))
            .collect();
        assert_eq!(
            seen, expected,
            "guest {sentinel:#x} must report its own sentinel (from its own \
             stack frame and its own v0) on every one of its own iterations, \
             in order"
        );
        assert_eq!(
            *report
                .exit_code
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(sentinel),
            "guest {sentinel:#x} must reach its own real exit"
        );
    }

    /// The scenario that hardware-disproved the previous per-thread design: a
    /// guest whose `SP` at its next syscall is *not* the `SP` it was resumed
    /// with. Single-threaded, so this isolates the `SP`-independence of the
    /// per-thread-state reach from the concurrency question below.
    #[test]
    fn a_guest_that_moves_its_sp_between_a_resume_and_its_next_syscall_still_round_trips() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();

        let report = run_sp_shifting_guest(0xFEED_FACE)
            .join()
            .expect("guest thread panicked");
        assert_sp_shift_report(&report, 0xFEED_FACE);
    }

    /// How many guest threads [`concurrent_guest_threads_each_keep_their_own_context`]
    /// runs at once. More than the two that would merely prove "not one", and
    /// enough to keep every performance core busy on this hardware.
    const CONCURRENT_GUESTS: usize = 8;

    /// The whole point of this row: several guest threads running *at the same
    /// time*, each keeping its own register file, its own vector file, its own
    /// stack and its own `PtRegs` across thousands of interleaved context
    /// switches -- with every one of them also moving its `SP` between each
    /// resume and its next syscall.
    ///
    /// Before this, a second concurrent `run_thread` panicked outright
    /// (`GUEST_ACTIVE`), because the host save area, the live-`PtRegs` pointer,
    /// the guest vector file and the ownership flag were process-global. A
    /// build that regressed any of them to process-global state would fail here
    /// by reporting another thread's sentinel, by desynchronising a trace, or
    /// by crashing the test process outright -- the same proof-by-survival the
    /// fault- and interrupt-routing tests rely on.
    #[test]
    fn concurrent_guest_threads_each_keep_their_own_context() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        publish_test_syscall_entry();
        crate::install_fault_handlers();

        let sentinels: Vec<usize> = (0..CONCURRENT_GUESTS)
            .map(|i| 0x0BAD_0000 + i * 0x1111 + 1)
            .collect();
        let threads: Vec<_> = sentinels
            .iter()
            .map(|&sentinel| (sentinel, run_sp_shifting_guest(sentinel)))
            .collect();

        for (sentinel, handle) in threads {
            let report = handle.join().expect("a guest thread panicked");
            assert_sp_shift_report(&report, sentinel);
        }
    }

    /// The mechanism every naked function in this module depends on: the raw
    /// `MRS TPIDRRO_EL0` + masked TSD load reaches exactly the storage
    /// `pthread_setspecific` writes, for a key this module reserved. Asserted
    /// rather than assumed because the whole per-thread design rests on it and
    /// nothing else in the build would notice if Darwin changed it.
    #[test]
    fn direct_tsd_read_sees_pthread_setspecific() {
        let _serial = TEST_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = reserve_guest_state_tsd_slot();
        assert!(
            current_guest_state().is_null(),
            "the test thread is not running a guest, so its slot starts clear"
        );

        let sentinel = 0xDEAD_BEEF_1234_5678_usize;
        // SAFETY: `key` is this module's own reserved, live key; storing an
        // opaque pointer-sized value has no precondition beyond that.
        assert_eq!(
            unsafe { libc::pthread_setspecific(key, sentinel as *const libc::c_void) },
            0
        );
        assert_eq!(
            current_guest_state() as usize,
            sentinel,
            "the raw TPIDRRO_EL0-relative read must observe pthread_setspecific"
        );
        // SAFETY: same key, same thread.
        assert_eq!(
            unsafe { libc::pthread_getspecific(key) } as usize,
            sentinel,
            "and pthread_getspecific must observe the same word"
        );
        // SAFETY: same key, same thread; leaves the slot as this test found it.
        assert_eq!(
            unsafe { libc::pthread_setspecific(key, core::ptr::null()) },
            0
        );
        assert!(current_guest_state().is_null());
    }

    /// `MRS X16, TPIDRRO_EL0`, the first instruction of every entry stub.
    /// Cross-checked against `litebox_syscall_rewriter::arm64`'s own
    /// `MRS_TPIDRRO_EL0_BITS` (`0xD53B_D060`, with the destination register in
    /// the low five bits).
    const MRS_X16_TPIDRRO_EL0: u32 = 0xD53B_D060 | 16;

    /// `LDR X16, [X16, #(slot * 8)]`: the unsigned-offset 64-bit load form,
    /// `1111_1001_01 imm12 Rn Rt`, with `imm12` the offset scaled by 8 (so it
    /// *is* the slot number), `Rn = Rt = 16`.
    fn expected_stub_load(slot: usize) -> u32 {
        0xF940_0000 | (u32::try_from(slot).unwrap() << 10) | (16 << 5) | 16
    }

    /// The entry-stub table is the entire mechanism that lets the syscall
    /// callback reach per-thread state with the one register the rewriter's
    /// `SVC` gate leaves free, and it is built with assembler `.rept`/`.set`
    /// directives whose per-iteration immediate is exactly the thing that could
    /// silently degenerate (an assembler that evaluated `litebox_tsd_slot` once
    /// would emit 768 identical stubs, all reading slot 0 -- libpthread's own
    /// `pthread_self` pointer -- and every existing test in this module would
    /// still pass on the single thread that reserved slot 0's neighbour).
    /// So read the emitted machine code back and check the immediates really
    /// vary, at both ends of the table and at the slot this process uses.
    #[test]
    fn every_tsd_slot_gets_its_own_entry_stub() {
        let base = syscall_entry_stubs as *const () as usize;
        let key = reserve_guest_state_tsd_slot();
        let reserved = usize::try_from(key).unwrap();

        for slot in [0, 1, 255, reserved, TSD_SLOT_COUNT - 1] {
            // SAFETY: reads two of the four instruction words of stub `slot`,
            // which is inside this function's own `.text`.
            let (mrs, ldr) = unsafe {
                let stub = (base + slot * TSD_STUB_BYTES) as *const u32;
                (stub.read(), stub.add(2).read())
            };
            assert_eq!(
                mrs, MRS_X16_TPIDRRO_EL0,
                "stub {slot} must anchor on TPIDRRO_EL0"
            );
            assert_eq!(
                ldr,
                expected_stub_load(slot),
                "stub {slot} must load TSD slot {slot}, not some other slot"
            );
        }

        assert_eq!(
            syscall_entry_point(),
            base + reserved * TSD_STUB_BYTES,
            "the reported entry point must be this process's own reserved slot's stub"
        );
    }
}
