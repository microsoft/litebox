// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! On Linux AArch64, default-off `aarch64_pacga` gives guests physical `TPIDR_EL0`.
//! It requires HWCAP_PACG and `PR_PAC_RESET_KEYS`, reserves APGA per guest thread,
//! and supports at most 1024 concurrent registrations per host process. Callbacks
//! trust exclusive APGA ownership; a raw reset can select another live thread's
//! slot without detection. It cannot coexist with `aarch64_virtualize_x18`.
//! Independent host signal handlers must recover host TP before compiled code
//! or not run during guest execution.
//!
//! Fingerprints select slots, not a security boundary. Signal recovery additionally
//! verifies fingerprint/TID because unregistered host threads can inherit keys.
//! Only APGA is reset; address PAC keys survive.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use litebox::utils::TruncateExt as _;

use super::tls_offset;

#[cfg(feature = "aarch64_virtualize_x18")]
compile_error!(
    "Linux AArch64 native TP (aarch64_pacga) is incompatible with aarch64_virtualize_x18"
);

#[repr(C)]
pub(super) struct TlsState {
    registration: usize,
}

const REGISTRATION_OFFSET: usize = core::mem::offset_of!(super::TlsBlock, tp_state)
    + core::mem::offset_of!(TlsState, registration);

// The generic key is reserved per guest thread and changes after fork.
pub(super) const RESERVED_CPU_FEATURES: litebox::arch::aarch64::CpuFeatures =
    litebox::arch::aarch64::CpuFeatures::PAUTH_GENERIC;

#[inline]
pub(super) fn assert_tls_placement() {}

// Registration owns this direct PACGA slot until guest execution ends; only
// registered guest threads enter the callback, and the protocol reserves APGA.
// This hot lookup does not verify TID/full fingerprint: resetting APGA outside
// Registration can select another live slot, not just the fatal missing-slot path.
// Use x16 and x17 spilled to the unused +24 slot, with no guest GPR/NZCV/vector
// clobbers or extra stack storage.
const _: () = assert!(
    litebox_trampoline::aarch64::SVC_FRAME_BYTES == 32
        && litebox_trampoline::aarch64::SVC_FRAME_OFF_STUB == 16
        && INDEX_SHIFT == 54
);

macro_rules! enter_host_tp {
    () => {
        concat!(
            ".arch_extension pauth\n",
            "str x17, [sp, #24]\n",
            "mov x16, xzr\n",
            "pacga x16, x16, x16\n",
            "lsr x16, x16, #54\n",
            "adrp x17, litebox_pacga_threads\n",
            "add x17, x17, :lo12:litebox_pacga_threads\n",
            "add x16, x17, x16, lsl #5\n",
            "ldar w17, [x16]\n",
            "cbz w17, 9f\n",
            "tbnz w17, #31, 9f\n",
            "ldr x16, [x16, #8]\n",
            "cbnz x16, 8f\n",
            "9:\n",
            // Fail without calling compiled code under an unknown TP.
            "b litebox_pacga_callback_fatal\n",
            "8:\n",
            "mrs x17, tpidr_el0\n",
            "msr tpidr_el0, x16\n",
            "add x16, x16, #:tprel_hi12:litebox_tls_block, lsl #12\n",
            "add x16, x16, #:tprel_lo12_nc:litebox_tls_block\n",
            "str x17, [x16, #{GUEST_TP}]\n",
            "ldr x17, [sp, #24]\n",
        )
    };
}

pub(super) use enter_host_tp;

// Requires x17 to point at the TLS block; clobbers only the supplied register.
macro_rules! enter_guest_tp {
    ($reg:literal) => {
        concat!(
            "ldr ",
            $reg,
            ", [x17, #{GUEST_TP}]\n",
            "msr tpidr_el0, ",
            $reg,
            "\n",
        )
    };
}

pub(super) use enter_guest_tp;

/// Guest TP is not virtualized; there are no TP gates.
pub(crate) fn guest_thread_pointer_offset() -> Option<usize> {
    None
}

/// Maximum simultaneous native guest threads. Collisions rekey rather than
/// share a slot, so the callback can recover using only x16 and spilled x17.
const CAPACITY: usize = 1024;
const INDEX_SHIFT: u32 = 54;
const REGISTRATION_ATTEMPTS: usize = CAPACITY * 16;
const CLAIMED: i32 = -1;

#[repr(C, align(32))]
struct Entry {
    tid: AtomicI32,
    host_tp: AtomicUsize,
    fingerprint: AtomicU64,
}

impl Entry {
    const fn new() -> Self {
        Self {
            tid: AtomicI32::new(0),
            host_tp: AtomicUsize::new(0),
            fingerprint: AtomicU64::new(0),
        }
    }

    fn claim(&self) -> bool {
        self.tid
            .compare_exchange(0, CLAIMED, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }
}

// Offsets are shared with the two-register callback and naked signal recovery.
// The callback indexes entries with `add ..., lsl #5`.
const _: () = assert!(size_of::<Entry>() == 1 << 5);
const _: () = assert!(core::mem::offset_of!(Entry, host_tp) == 8);
const _: () = assert!(core::mem::offset_of!(Entry, fingerprint) == 16);
const _: () = assert!(CAPACITY == 1 << (64 - INDEX_SHIFT));

#[unsafe(no_mangle)]
static litebox_pacga_threads: [Entry; CAPACITY] = [const { Entry::new() }; CAPACITY];

fn reset_key() -> Result<(), syscalls::Errno> {
    // SAFETY: this exact prctl resets only this thread's APGA key, no pointers.
    unsafe {
        syscalls::syscall5(
            syscalls::Sysno::prctl,
            libc::PR_PAC_RESET_KEYS as usize,
            libc::PR_PAC_APGAKEY.trunc(),
            0,
            0,
            0,
        )?;
    }
    Ok(())
}

fn fingerprint() -> u64 {
    let value;
    // SAFETY: PACGA reads only registers and the APGA key, which is reserved.
    unsafe {
        core::arch::asm!(
            ".arch_extension pauth",
            "mov {value}, xzr",
            "pacga {value}, {value}, {value}",
            value = out(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

fn host_tp() -> usize {
    let tp;
    // SAFETY: all Rust callers execute with the host TP installed.
    unsafe {
        core::arch::asm!("mrs {tp}, tpidr_el0", tp = out(reg) tp,
            options(nomem, nostack, preserves_flags));
    }
    tp
}

fn registration_slot() -> *mut usize {
    (host_tp() + tprel_offset!(litebox_tls_block) + REGISTRATION_OFFSET) as *mut usize
}

// Teardown accesses own-thread TLS and must run on the registering thread.
pub(crate) struct Registration(Option<usize>, PhantomData<*const ()>);

impl Registration {
    pub(crate) fn enter() -> Self {
        let slot = registration_slot();
        // SAFETY: own-thread TLS, used only while executing host code.
        if unsafe { slot.read() } != 0 {
            return Self(None, PhantomData);
        }
        // SAFETY: raw gettid avoids libc's copied identity after native fork.
        let tid = unsafe { syscalls::syscall0(syscalls::Sysno::gettid) }.unwrap();
        let tid = i32::try_from(tid).expect("kernel TID fits i32");
        for _ in 0..REGISTRATION_ATTEMPTS {
            reset_key().expect("aarch64_pacga: failed to reset APGA key");
            let fingerprint = fingerprint();
            let index = (fingerprint >> INDEX_SHIFT) as usize;
            let entry = &litebox_pacga_threads[index];
            if !entry.claim() {
                continue;
            }
            entry.host_tp.store(host_tp(), Ordering::Relaxed);
            entry.fingerprint.store(fingerprint, Ordering::Relaxed);
            // Signals either see no registration (and already have host TP)
            // or this complete entry. No reader waits on a writer.
            entry.tid.store(tid, Ordering::Release);
            // SAFETY: publication is complete before native guest entry.
            unsafe { slot.write(index + 1) };
            return Self(Some(index), PhantomData);
        }
        panic!(
            "aarch64_pacga: registration table exhausted or repeated slot collisions (capacity {CAPACITY})"
        );
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(index) = self.0 {
            // No guest executes during teardown. Removing identity first means
            // a signal cannot follow stale TLS, even if another thread reuses
            // the slot. Kernel TIDs cannot be reused until this thread exits.
            litebox_pacga_threads[index].tid.store(0, Ordering::Release);
            // SAFETY: own-thread TLS; outer registration owns this slot.
            unsafe { registration_slot().write(0) };
        }
    }
}

/// Called in the sole surviving fork child while TP is still the host TP.
/// The copied guest stack, including its registration guard, must not resume.
pub(crate) unsafe fn reset_after_fork() {
    for entry in &litebox_pacga_threads {
        entry.tid.store(0, Ordering::Relaxed);
        entry.host_tp.store(0, Ordering::Relaxed);
        entry.fingerprint.store(0, Ordering::Relaxed);
    }
    // SAFETY: sole surviving thread, inherited TLS is still mapped.
    unsafe { registration_slot().write(0) };
}

static CALLBACK_FAILURE_MESSAGE: &[u8] =
    b"litebox: aarch64_pacga callback has no live registration (APGA ownership required)\n";
const CALLBACK_FAILURE_STATUS: i32 = 190;

// No host TP is known on this path. Use only raw syscalls, even for diagnostics.
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn litebox_pacga_callback_fatal() -> ! {
    core::arch::naked_asm!(
        "mov x0, #{STDERR}",
        "adrp x1, {MESSAGE}",
        "add x1, x1, :lo12:{MESSAGE}",
        "ldr x1, [x1]",
        "mov x2, #{LENGTH}",
        "mov x8, #{WRITE}",
        "svc #0",
        "mov x0, #{STATUS}",
        "mov x8, #{EXIT_GROUP}",
        "svc #0",
        "brk #0",
        STDERR = const libc::STDERR_FILENO,
        MESSAGE = sym CALLBACK_FAILURE_MESSAGE,
        LENGTH = const CALLBACK_FAILURE_MESSAGE.len(),
        WRITE = const libc::SYS_write,
        STATUS = const CALLBACK_FAILURE_STATUS,
        EXIT_GROUP = const libc::SYS_exit_group,
    );
}

/// Returns the entry TP in x16, installs host TP if and only if both the full
/// fingerprint and raw kernel TID match. Inherited keys on unregistered host
/// threads therefore never redirect TLS to their creator. No Rust/libc, locks,
/// allocation, FP state, or unbounded retry is involved.
#[unsafe(naked)]
unsafe extern "C" fn recover_signal_host_tp() {
    core::arch::naked_asm!(
        ".arch_extension pauth",
        "stp x0, x1, [sp, #-80]!",
        "stp x2, x3, [sp, #16]",
        "stp x8, x17, [sp, #32]",
        "str x30, [sp, #48]",
        "mrs x16, nzcv",
        "str x16, [sp, #56]",
        "mrs x16, tpidr_el0",
        "str x16, [sp, #64]",
        "mov x8, #{GETTID}",
        "svc #0",
        "mov x2, x0",
        "mov x3, xzr",
        "pacga x3, x3, x3",
        "lsr x16, x3, #{SHIFT}",
        "adrp x17, {TABLE}",
        "add x17, x17, :lo12:{TABLE}",
        "add x17, x17, x16, lsl #5",
        "ldar w0, [x17]",
        "eor w0, w0, w2",
        "cbnz w0, 2f",
        "ldr x0, [x17, #16]",
        "eor x0, x0, x3",
        "cbnz x0, 2f",
        "ldr x0, [x17, #8]",
        "cbz x0, 2f",
        "msr tpidr_el0, x0",
        "2:",
        "ldr x16, [sp, #56]",
        "msr nzcv, x16",
        "ldp x0, x1, [sp]",
        "ldp x2, x3, [sp, #16]",
        "ldp x8, x17, [sp, #32]",
        "ldr x30, [sp, #48]",
        "ldr x16, [sp, #64]",
        "add sp, sp, #80",
        "ret",
        ".globl litebox_pacga_recovery_end",
        "litebox_pacga_recovery_end:",
        TABLE = sym litebox_pacga_threads,
        GETTID = const libc::SYS_gettid,
        SHIFT = const INDEX_SHIFT,
    );
}

// Wrappers run on the kernel-selected signal stack. Clear in_guest before any
// compiled code; the saved byte is an argument rather than a TLS global, so a
// nested handler cannot consume its parent's guest state. On a transparent
// return restore both the byte and the exact interrupted TP. Linux sigreturn
// restores neither TP nor our TLS marker.
macro_rules! signal_entry {
    ($name:ident, $end:ident, $handler:ident) => {
        #[unsafe(naked)]
        pub(crate) unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "sub sp, sp, #64",
                "str x2, [sp, #16]",
                "bl {recover}",
                "str x16, [sp, #32]",
                load_tls_block_base!("x17"),
                "ldrb w3, [x17, #{IN_GUEST}]",
                "str w3, [sp, #40]",
                "mov x4, x16",
                "strb wzr, [x17, #{IN_GUEST}]",
                "bl {handler}",
                "ldr x2, [sp, #16]",
                "ldr x16, [x2, #{PC}]",
                "adrp x17, exception_callback",
                "add x17, x17, :lo12:exception_callback",
                "cmp x16, x17",
                "b.eq 2f",
                "adrp x17, interrupt_callback",
                "add x17, x17, :lo12:interrupt_callback",
                "cmp x16, x17",
                "b.eq 2f",
                load_tls_block_base!("x17"),
                "ldr w16, [sp, #40]",
                "strb w16, [x17, #{IN_GUEST}]",
                "ldr x16, [sp, #32]",
                "msr tpidr_el0, x16",
                "2:",
                // Entry SP points at the kernel sigframe. Kernel sigreturn
                // restores all GPRs; never RET to an unclassified vDSO restorer
                // with the guest marker/TP already reinstalled.
                "add sp, sp, #64",
                "mov x8, #{RT_SIGRETURN}",
                "svc #0",
                "brk #0",
                concat!(".globl ", stringify!($end)),
                concat!(stringify!($end), ":"),
                recover = sym recover_signal_host_tp,
                handler = sym $handler,
                IN_GUEST = const tls_offset::IN_GUEST,
                RT_SIGRETURN = const libc::SYS_rt_sigreturn,
                PC = const core::mem::offset_of!(libc::ucontext_t, uc_mcontext)
                    + core::mem::offset_of!(libc::mcontext_t, pc),
            );
        }
    };
}

signal_entry!(
    exception_entry,
    litebox_pacga_exception_end,
    dispatch_exception
);
signal_entry!(
    interrupt_entry,
    litebox_pacga_interrupt_end,
    dispatch_interrupt
);

#[derive(Clone, Copy)]
pub(crate) struct SignalEntry {
    // Direct host-side tests have no wrapper snapshot and read the live marker.
    in_guest: Option<u8>,
    tp: usize,
}

unsafe extern "C" fn dispatch_exception(
    signal: i32,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
    in_guest: u8,
    tp: usize,
) {
    // SAFETY: wrapper received kernel signal arguments and restored host TP.
    unsafe {
        super::super::exception_signal_handler(
            signal,
            info,
            context,
            SignalEntry {
                in_guest: Some(in_guest),
                tp,
            },
        );
    }
}

unsafe extern "C" fn dispatch_interrupt(
    signal: i32,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
    in_guest: u8,
    tp: usize,
) {
    // SAFETY: as for dispatch_exception.
    unsafe {
        super::super::interrupt_signal_handler(
            signal,
            info,
            context,
            SignalEntry {
                in_guest: Some(in_guest),
                tp,
            },
        );
    }
}

unsafe extern "C" {
    fn litebox_pacga_recovery_end();
    fn litebox_pacga_exception_end();
    fn litebox_pacga_interrupt_end();
}

fn in_signal_transition(pc: usize) -> bool {
    [
        (
            recover_signal_host_tp as *const () as usize,
            litebox_pacga_recovery_end as *const () as usize,
        ),
        (
            exception_entry as *const () as usize,
            litebox_pacga_exception_end as *const () as usize,
        ),
        (
            interrupt_entry as *const () as usize,
            litebox_pacga_interrupt_end as *const () as usize,
        ),
    ]
    .into_iter()
    .any(|(start, end)| (start..end).contains(&pc))
}

impl SignalEntry {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self {
            in_guest: None,
            tp: 0,
        }
    }

    #[inline]
    pub(crate) fn in_exception_prologue(pc: usize) -> bool {
        in_signal_transition(pc) || super::in_syscall_callback_prologue(pc)
    }

    pub(crate) fn capture_guest_tp(self, pc: usize) {
        if self.in_guest.is_some_and(|in_guest| in_guest != 0)
            && !super::in_switch_to_guest(pc)
            && !super::in_syscall_callback_prologue(pc)
            && !in_signal_transition(pc)
        {
            super::set_guest_thread_pointer(self.tp);
        }
    }

    pub(crate) fn take_guest(self) -> Option<*mut litebox_common_linux::PtRegs> {
        super::signal_handler_take_guest(self.in_guest)
    }

    pub(crate) fn take_interrupted_guest(
        self,
        pc: usize,
    ) -> Option<*mut litebox_common_linux::PtRegs> {
        self.capture_guest_tp(pc);
        if in_signal_transition(pc) {
            super::signal_handler_set_interrupt();
            None
        } else {
            self.take_guest()
        }
    }
}

pub(crate) fn add_seccomp_rules(rules: &mut Vec<(i64, Vec<seccompiler::SeccompRule>)>) {
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
    rules.push((
        libc::SYS_prctl,
        vec![
            SeccompRule::new(
                [
                    libc::PR_PAC_RESET_KEYS as u64,
                    libc::PR_PAC_APGAKEY,
                    0,
                    0,
                    0,
                ]
                .into_iter()
                .zip(0_u8..)
                .map(|(value, index)| {
                    SeccompCondition::new(index, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, value)
                        .unwrap()
                })
                .collect(),
            )
            .unwrap(),
        ],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::{self, get_guest_thread_pointer, tls_offset};
    use litebox::platform::GuestVectorStateProvider as _;
    use litebox::shim::{ContinueOperation, EnterShim, ExceptionInfo};
    use litebox::utils::TruncateExt;
    use litebox_common_linux::{GuestVectorState, PtRegs};
    use std::cell::Cell;

    fn isolated(name: &str, body: impl FnOnce()) {
        if !crate::tests::reexec_test_if_needed(&format!("arch::aarch64_pacga::tests::{name}")) {
            body();
        }
    }

    fn recovered_tp() -> usize {
        let tp;
        // SAFETY: the special helper preserves all but x16 and installs host TP.
        unsafe {
            core::arch::asm!("bl {recover}", recover = sym recover_signal_host_tp,
                lateout("x16") tp, out("x30") _, options(preserves_flags));
        }
        tp
    }

    #[test]
    fn registration_collision_exhaustion_and_reuse() {
        isolated("registration_collision_exhaustion_and_reuse", || {
            let local = Entry::new();
            assert!(local.claim());
            assert!(!local.claim());
            local.tid.store(0, Ordering::Release);
            assert!(local.claim());

            for entry in &litebox_pacga_threads {
                assert!(entry.claim());
            }
            assert!(std::panic::catch_unwind(Registration::enter).is_err());
            assert_eq!(unsafe { registration_slot().read() }, 0);
            for entry in &litebox_pacga_threads {
                entry.tid.store(0, Ordering::Release);
            }
            let tp = host_tp();
            for _ in 0..128 {
                let registration = Registration::enter();
                let index = registration.0.unwrap();
                assert_eq!(recovered_tp(), tp);
                let nested = Registration::enter();
                assert!(nested.0.is_none());
                drop(nested);
                assert_ne!(litebox_pacga_threads[index].tid.load(Ordering::Acquire), 0);
                drop(registration);
                assert_eq!(litebox_pacga_threads[index].tid.load(Ordering::Acquire), 0);
                assert_eq!(unsafe { registration_slot().read() }, 0);
                assert_eq!(recovered_tp(), tp);
            }
        });
    }

    #[test]
    fn signal_lookup_rejects_partial_publication_wrong_fingerprint_and_teardown() {
        isolated(
            "signal_lookup_rejects_partial_publication_wrong_fingerprint_and_teardown",
            || {
                crate::LinuxUserland::new();
                let tp = host_tp();
                let fingerprint = fingerprint();
                let entry = &litebox_pacga_threads[(fingerprint >> INDEX_SHIFT) as usize];
                let tid = i32::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
                let signal = crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed);
                assert!(entry.claim());
                // If any incomplete/dead/wrong-key entry is accepted, real signal
                // entry will execute compiled code under an invalid TP and fail.
                entry.host_tp.store(TP1, Ordering::Relaxed);
                entry.fingerprint.store(fingerprint, Ordering::Relaxed);
                for (owner, key) in [
                    (CLAIMED, fingerprint),
                    (tid, fingerprint ^ 1),
                    (0, fingerprint),
                ] {
                    entry.fingerprint.store(key, Ordering::Relaxed);
                    entry.tid.store(owner, Ordering::Release);
                    assert_eq!(
                        unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                        0
                    );
                    assert_eq!(host_tp(), tp);
                }
                entry.host_tp.store(tp, Ordering::Relaxed);
                entry.fingerprint.store(fingerprint, Ordering::Relaxed);
                entry.tid.store(tid, Ordering::Release);
                assert_eq!(
                    unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                    0
                );
                assert_eq!(host_tp(), tp);
                entry.tid.store(0, Ordering::Release);
            },
        );
    }

    #[test]
    fn inherited_key_host_thread_does_not_recover_creator_tls() {
        isolated(
            "inherited_key_host_thread_does_not_recover_creator_tls",
            || {
                let _platform = crate::LinuxUserland::new();
                let registration = Registration::enter();
                let creator_fingerprint = fingerprint();
                let creator_tp = host_tp();
                std::thread::spawn(move || {
                    assert_eq!(fingerprint(), creator_fingerprint, "clone inherits APGA");
                    let tp = host_tp();
                    assert_ne!(tp, creator_tp);
                    assert_eq!(recovered_tp(), tp);
                    assert_eq!(host_tp(), tp, "raw TID must reject creator's slot");
                    let signal = crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed);
                    assert_eq!(
                        unsafe { libc::pthread_kill(libc::pthread_self(), signal) },
                        0
                    );
                    assert_eq!(host_tp(), tp, "real naked signal entry must keep own TLS");
                    let _own = Registration::enter();
                    assert_eq!(recovered_tp(), tp);
                })
                .join()
                .unwrap();
                assert_eq!(host_tp(), creator_tp);
                drop(registration);
            },
        );
    }

    struct GuestStack {
        mapping: *mut libc::c_void,
        size: usize,
        sp: usize,
    }

    impl GuestStack {
        fn new() -> Self {
            let page = 4096;
            let mapping = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    page * 2,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            assert_eq!(unsafe { libc::mprotect(mapping, page, libc::PROT_NONE) }, 0);
            Self {
                mapping,
                size: page * 2,
                sp: mapping as usize + page + 32,
            }
        }
    }

    impl Drop for GuestStack {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::munmap(self.mapping, self.size) }, 0);
        }
    }

    // These use the existing 32-byte gate ABI without depending on the rewriter.
    // The sole writable gate frame starts immediately above a PROT_NONE page.
    macro_rules! gate {
        ($resume:literal, $stub:literal) => {
            concat!(
                "sub sp, sp, #32\nstr x16, [sp]\n",
                "adr x16, ",
                $resume,
                "\nstr x16, [sp, #8]\n",
                "adr x16, ",
                $stub,
                "\nstr x16, [sp, #16]\n",
                "adrp x16, syscall_callback\nadd x16, x16, :lo12:syscall_callback\nbr x16\n",
                $stub,
                ":\nldr x16, [sp]\nadd sp, sp, #32\nb ",
                $resume,
                "\n",
                $resume,
                ":\n",
            )
        };
    }

    #[unsafe(naked)]
    unsafe extern "C" fn syscall_guest() {
        core::arch::naked_asm!(
            "msr tpidr_el0, x0",
            "mrs x18, tpidr_el0",
            gate!(".Lsys_resume1", ".Lsys_stub1"),
            "msr tpidr_el0, x0",
            "mrs x18, tpidr_el0",
            gate!(".Lsys_resume2", ".Lsys_stub2"),
            "brk #0",
        );
    }

    #[unsafe(naked)]
    unsafe extern "C" fn exception_guest() {
        core::arch::naked_asm!(
            "msr tpidr_el0, x0",
            "brk #0",
            "mrs x18, tpidr_el0",
            gate!(".Lexc_resume", ".Lexc_stub"),
            "brk #0",
        );
    }

    #[unsafe(naked)]
    unsafe extern "C" fn interrupt_guest() {
        core::arch::naked_asm!(
            "msr tpidr_el0, x3",
            "mov x8, #{TGKILL}",
            "svc #0",
            "mrs x18, tpidr_el0",
            gate!(".Lirq_resume", ".Lirq_stub"),
            "brk #0",
            TGKILL = const libc::SYS_tgkill,
        );
    }

    const TP1: usize = 0x1234_5000;
    const TP2: usize = 0x7654_3000;
    const NZCV: u64 = 0xa000_0000;

    fn vectors() -> GuestVectorState {
        let mut state = GuestVectorState::default();
        state.set_fpsimd(
            &core::array::from_fn(|i| (i as u128 + 1) * 0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            1,
            1 << 22,
        );
        state
    }

    struct Shim {
        platform: &'static crate::LinuxUserland,
        original: PtRegs,
        calls: Cell<usize>,
        interrupts: Cell<usize>,
        exceptions: Cell<usize>,
        kind: usize,
    }

    impl Shim {
        fn check(&self, ctx: &PtRegs, tp: usize) {
            assert_eq!(get_guest_thread_pointer(), tp);
            assert_eq!(ctx.pstate & 0xf000_0000, NZCV);
            for i in 1..31 {
                if i != 8 && i != 18 {
                    assert_eq!(ctx.regs[i], self.original.regs[i], "x{i}");
                }
            }
            assert_eq!(
                ctx.regs[8],
                if self.kind == 2 {
                    usize::try_from(libc::SYS_tgkill).unwrap()
                } else {
                    self.original.regs[8]
                }
            );
            let state = self.platform.get_guest_vector_state();
            assert_eq!(state.vregs(), vectors().vregs());
            assert_eq!(state.fpsr(), vectors().fpsr());
            assert_eq!(state.fpcr(), vectors().fpcr());
        }
    }

    impl EnterShim for Shim {
        type ExecutionContext = PtRegs;
        fn init(&self, _: &mut PtRegs) -> ContinueOperation {
            ContinueOperation::Resume
        }
        fn syscall(&self, ctx: &mut PtRegs) -> ContinueOperation {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            let tp = if self.kind == 0 && calls == 1 {
                TP2
            } else {
                TP1
            };
            self.check(ctx, tp);
            assert_eq!(ctx.regs[18], tp);
            assert_eq!(ctx.sp, self.original.sp);
            assert_eq!(ctx.orig_x0, if self.kind == 2 { 0 } else { tp });
            if self.kind == 0 && calls == 0 {
                ctx.regs[0] = TP2;
                ContinueOperation::Resume
            } else {
                ContinueOperation::Terminate
            }
        }
        fn exception(&self, ctx: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
            assert_eq!(self.kind, 1);
            self.check(ctx, TP1);
            assert_eq!(ctx.pc, exception_guest as *const () as usize + 4);
            self.exceptions.set(self.exceptions.get() + 1);
            ctx.pc += 4;
            ContinueOperation::Resume
        }
        fn interrupt(&self, ctx: &mut PtRegs) -> ContinueOperation {
            self.check(ctx, TP1);
            self.interrupts.set(self.interrupts.get() + 1);
            ContinueOperation::Resume
        }
    }

    fn live_fp() -> (u64, u64) {
        let (status, control);
        // SAFETY: reads architectural FP state only.
        unsafe {
            core::arch::asm!("mrs {status}, fpsr", "mrs {control}, fpcr",
            status = out(reg) status, control = out(reg) control,
            options(nomem, nostack, preserves_flags));
        }
        (status, control)
    }

    fn run_guest(kind: usize) {
        let platform = crate::LinuxUserland::new();
        let tp = host_tp();
        let fp_before = live_fp();
        let stack = GuestStack::new();
        let mut ctx = PtRegs::default();
        for (i, reg) in ctx.regs.iter_mut().enumerate() {
            *reg = 0x1000_0000_0000_0000 | i;
        }
        ctx.regs[0] = TP1;
        ctx.sp = stack.sp;
        ctx.pc = match kind {
            0 => syscall_guest as *const () as usize,
            1 => exception_guest as *const () as usize,
            _ => interrupt_guest as *const () as usize,
        };
        ctx.pstate = NZCV;
        if kind == 2 {
            ctx.regs[0] = usize::try_from(unsafe { libc::getpid() }).unwrap();
            ctx.regs[1] = usize::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
            ctx.regs[2] =
                usize::try_from(crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed)).unwrap();
            ctx.regs[3] = TP1;
        }
        let shim = Shim {
            platform,
            original: ctx.clone(),
            calls: Cell::new(0),
            interrupts: Cell::new(0),
            exceptions: Cell::new(0),
            kind,
        };
        platform.set_guest_vector_state(&vectors());
        // SAFETY: valid executable code and aligned stack, guest terminates in shim.
        unsafe { crate::run_thread_ref(&shim, &mut ctx) };
        assert_eq!(host_tp(), tp);
        assert_eq!(live_fp(), fp_before);
        assert_eq!(shim.calls.get(), if kind == 0 { 2 } else { 1 });
        assert_eq!(shim.exceptions.get(), usize::from(kind == 1));
        assert_eq!(shim.interrupts.get(), usize::from(kind == 2));
        assert_eq!(unsafe { registration_slot().read() }, 0);
    }

    #[test]
    fn physical_tp_syscall_and_outbound_resume_at_guard_page() {
        isolated(
            "physical_tp_syscall_and_outbound_resume_at_guard_page",
            || run_guest(0),
        );
    }

    #[test]
    fn physical_tp_exception_and_generic_resume() {
        isolated("physical_tp_exception_and_generic_resume", || run_guest(1));
    }

    #[test]
    fn physical_tp_fault_probe_nests_without_overwriting_guest_state() {
        isolated(
            "physical_tp_fault_probe_nests_without_overwriting_guest_state",
            || {
                struct FaultShim(Shim);
                impl EnterShim for FaultShim {
                    type ExecutionContext = PtRegs;
                    fn init(&self, _: &mut PtRegs) -> ContinueOperation {
                        ContinueOperation::Resume
                    }
                    fn syscall(&self, _: &mut PtRegs) -> ContinueOperation {
                        unreachable!()
                    }
                    fn interrupt(&self, _: &mut PtRegs) -> ContinueOperation {
                        unreachable!()
                    }
                    fn exception(&self, ctx: &mut PtRegs, _: &ExceptionInfo) -> ContinueOperation {
                        self.0.check(ctx, TP1);
                        assert_eq!(ctx.pc, self.0.original.pc + 4);
                        self.0.exceptions.set(1);
                        ContinueOperation::Terminate
                    }
                }
                let platform = crate::LinuxUserland::new();
                let stack = GuestStack::new();
                let code = GuestStack::new();
                let start = code.mapping as usize + 4096;
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        exception_guest as *const u8,
                        start as *mut u8,
                        8,
                    );
                    // Valid SVC metadata for a candidate starting in the guard page.
                    // Classification must fault through memcpy_fallible's exception
                    // table in a nested SIGSEGV, then retain the original guest BRK.
                    ((start + 44) as *mut u32).write(0x0001_b807);
                }
                arch::sync_instruction_stream(start..start + 4096);
                assert_eq!(
                    unsafe {
                        libc::mprotect(start as *mut _, 4096, libc::PROT_READ | libc::PROT_EXEC)
                    },
                    0
                );
                let mut ctx = PtRegs {
                    regs: core::array::from_fn(|i| 0x1000_0000_0000_0000 | i),
                    ..PtRegs::default()
                };
                ctx.regs[0] = TP1;
                ctx.pc = start;
                ctx.sp = stack.sp;
                ctx.pstate = NZCV;
                let shim = FaultShim(Shim {
                    platform,
                    original: ctx.clone(),
                    calls: Cell::new(0),
                    interrupts: Cell::new(0),
                    exceptions: Cell::new(0),
                    kind: 1,
                });
                platform.set_guest_vector_state(&vectors());
                let tp = host_tp();
                unsafe { crate::run_thread_ref(&shim, &mut ctx) };
                assert_eq!(shim.0.exceptions.get(), 1);
                assert_eq!(host_tp(), tp);
            },
        );
    }

    #[test]
    fn physical_tp_interrupt_and_generic_resume() {
        isolated("physical_tp_interrupt_and_generic_resume", || run_guest(2));
    }

    signal_entry!(nested_entry, litebox_pacga_nested_end, dispatch_nested);

    struct SignalTestState {
        nested_host_tp: AtomicUsize,
        nested_count: AtomicUsize,
    }

    static SIGNAL_TEST_STATE: SignalTestState = SignalTestState {
        nested_host_tp: AtomicUsize::new(0),
        nested_count: AtomicUsize::new(0),
    };

    unsafe extern "C" fn dispatch_nested(
        signal: i32,
        _: &mut libc::siginfo_t,
        _: &mut libc::ucontext_t,
        in_guest: u8,
        tp: usize,
    ) {
        // Avoid panicking across the signal ABI; a failed check exits the child.
        let host = SIGNAL_TEST_STATE.nested_host_tp.load(Ordering::Relaxed);
        let valid = host_tp() == host
            && if signal == libc::SIGUSR1 {
                in_guest == 1 && tp == TP1
            } else {
                in_guest == 0 && tp == host
            };
        if !valid {
            unsafe { libc::_exit(10) };
        }
        SIGNAL_TEST_STATE
            .nested_count
            .fetch_add(1, Ordering::Relaxed);
        if signal == libc::SIGUSR1 {
            unsafe {
                let pid = syscalls::syscall0(syscalls::Sysno::getpid).unwrap();
                let tid = syscalls::syscall0(syscalls::Sysno::gettid).unwrap();
                let _ =
                    syscalls::syscall3(syscalls::Sysno::tgkill, pid, tid, libc::SIGUSR2 as usize);
            }
            if SIGNAL_TEST_STATE.nested_count.load(Ordering::Relaxed) != 2 || host_tp() != host {
                unsafe { libc::_exit(11) };
            }
        }
    }

    #[test]
    fn physical_tp_nested_signal_returns_to_exact_interrupted_tp() {
        isolated(
            "physical_tp_nested_signal_returns_to_exact_interrupted_tp",
            || {
                // interrupt_guest sends x2; substitute SIGUSR1 rather than the runtime
                // interrupt. Both wrappers return transparently to physical guest TP.
                let platform = crate::LinuxUserland::new();
                SIGNAL_TEST_STATE
                    .nested_host_tp
                    .store(host_tp(), Ordering::Relaxed);
                for signal in [libc::SIGUSR1, libc::SIGUSR2] {
                    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
                    action.sa_sigaction = nested_entry as *const () as usize;
                    action.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_NODEFER;
                    assert_eq!(
                        unsafe {
                            libc::sigaction(signal, &raw const action, core::ptr::null_mut())
                        },
                        0
                    );
                }
                let stack = GuestStack::new();
                let mut ctx = PtRegs {
                    regs: core::array::from_fn(|i| 0x1000_0000_0000_0000 | i),
                    ..PtRegs::default()
                };
                ctx.regs[0] = usize::try_from(unsafe { libc::getpid() }).unwrap();
                ctx.regs[1] = usize::try_from(unsafe { libc::syscall(libc::SYS_gettid) }).unwrap();
                ctx.regs[2] = libc::SIGUSR1 as usize;
                ctx.regs[3] = TP1;
                ctx.sp = stack.sp;
                ctx.pc = interrupt_guest as *const () as usize;
                ctx.pstate = NZCV;
                let shim = Shim {
                    platform,
                    original: ctx.clone(),
                    calls: Cell::new(0),
                    interrupts: Cell::new(0),
                    exceptions: Cell::new(0),
                    kind: 2,
                };
                platform.set_guest_vector_state(&vectors());
                unsafe { crate::run_thread_ref(&shim, &mut ctx) };
                assert_eq!(SIGNAL_TEST_STATE.nested_count.load(Ordering::Relaxed), 2);
                assert_eq!(shim.calls.get(), 1);
                assert_eq!(shim.interrupts.get(), 0);
                assert_eq!(
                    host_tp(),
                    SIGNAL_TEST_STATE.nested_host_tp.load(Ordering::Relaxed)
                );
            },
        );
    }

    #[test]
    fn seccomp_prctl_allows_only_exact_apga_reset() {
        isolated("seccomp_prctl_allows_only_exact_apga_reset", || {
            crate::LinuxUserland::new();
            crate::LinuxUserland::enable_seccomp_filter(
                &[],
                &[],
                crate::SeccompScope::CallingThread,
                None,
                None,
            );
            assert_eq!(reset_key(), Ok(()));
            let allowed = [
                libc::PR_PAC_RESET_KEYS as usize,
                libc::PR_PAC_APGAKEY.trunc(),
                0,
                0,
                0,
            ];
            for (index, value) in [
                (0, libc::PR_GET_DUMPABLE as usize),
                (0, libc::PR_PAC_RESET_KEYS as usize | 1 << 32),
                (1, 0),
                (1, 1),
                (1, TruncateExt::<usize>::trunc(libc::PR_PAC_APGAKEY) | 1),
                (
                    1,
                    TruncateExt::<usize>::trunc(libc::PR_PAC_APGAKEY) | 1 << 32,
                ),
                (2, 1),
                (3, 1),
                (4, 1),
            ] {
                let mut args = allowed;
                args[index] = value;
                let result = unsafe {
                    syscalls::syscall5(
                        syscalls::Sysno::prctl,
                        args[0],
                        args[1],
                        args[2],
                        args[3],
                        args[4],
                    )
                };
                assert_eq!(result, Err(syscalls::Errno::EINVAL), "args {args:?}");
            }
        });
    }

    #[test]
    fn fork_discards_vanished_registrations_and_rekeys_survivor() {
        isolated(
            "fork_discards_vanished_registrations_and_rekeys_survivor",
            || {
                crate::LinuxUserland::new();
                let _registration = Registration::enter();
                let (send, receive) = std::sync::mpsc::channel();
                let (stop, wait) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let _registration = Registration::enter();
                    send.send(()).unwrap();
                    wait.recv().unwrap();
                });
                receive.recv().unwrap();
                let child = unsafe {
                    libc::syscall(
                        libc::SYS_clone,
                        libc::SIGCHLD,
                        0usize,
                        core::ptr::null_mut::<i32>(),
                        core::ptr::null_mut::<i32>(),
                        0usize,
                    )
                };
                assert!(child >= 0);
                if child == 0 {
                    // No copied registration guard or harness state is destroyed.
                    unsafe { crate::reset_current_thread_after_process_clone() };
                    assert!(
                        litebox_pacga_threads
                            .iter()
                            .all(|e| e.tid.load(Ordering::Acquire) == 0)
                    );
                    assert_eq!(unsafe { registration_slot().read() }, 0);
                    run_guest(0);
                    unsafe { libc::_exit(0) };
                }
                let child = i32::try_from(child).unwrap();
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                stop.send(()).unwrap();
                worker.join().unwrap();
            },
        );
    }

    #[test]
    fn native_transition_boundaries_preserve_saved_context() {
        isolated(
            "native_transition_boundaries_preserve_saved_context",
            || {
                extern "C" fn forwarded_exception(
                    _: i32,
                    info: &mut libc::siginfo_t,
                    _: &mut libc::ucontext_t,
                ) {
                    info.si_errno += 1;
                }
                let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
                action.sa_sigaction = forwarded_exception as *const () as usize;
                action.sa_flags = libc::SA_SIGINFO;
                assert_eq!(
                    unsafe {
                        libc::sigaction(libc::SIGSEGV, &raw const action, core::ptr::null_mut())
                    },
                    0,
                );
                let platform = crate::LinuxUserland::new();
                let _registration = Registration::enter();
                platform.set_guest_vector_state(&vectors());
                let block = host_tp() + tprel_offset!(litebox_tls_block);
                let mut regs = PtRegs {
                    pc: 0x1000,
                    sp: 0x2000,
                    regs: core::array::from_fn(|i| 0x3000 + i),
                    ..PtRegs::default()
                };
                let before = regs.clone();
                unsafe {
                    ((block + tls_offset::GUEST_CONTEXT_TOP) as *mut usize)
                        .write((&raw mut regs).add(1) as usize);
                }
                arch::set_guest_thread_pointer(TP1);
                let ranges = [
                    (
                        recover_signal_host_tp as *const () as usize,
                        litebox_pacga_recovery_end as *const () as usize,
                        false,
                    ),
                    (
                        exception_entry as *const () as usize,
                        litebox_pacga_exception_end as *const () as usize,
                        false,
                    ),
                    (
                        interrupt_entry as *const () as usize,
                        litebox_pacga_interrupt_end as *const () as usize,
                        false,
                    ),
                    (
                        arch::syscall_callback as *const () as usize,
                        arch::syscall_callback_in_guest_cleared as *const () as usize,
                        false,
                    ),
                    (
                        arch::switch_to_guest_via_outbound_stub_start as *const () as usize,
                        arch::switch_to_guest_via_outbound_stub_end as *const () as usize,
                        true,
                    ),
                    (
                        arch::switch_to_guest_via_sigreturn_start as *const () as usize,
                        arch::switch_to_guest_via_sigreturn_end as *const () as usize,
                        true,
                    ),
                ];
                for (start, end, redirect) in ranges {
                    assert!(start < end);
                    for pc in (start..end).step_by(4) {
                        for interrupt in [false, true] {
                            if !interrupt && redirect {
                                continue;
                            }
                            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
                            context.uc_mcontext.pc = pc as u64;
                            context.uc_mcontext.sp = 0xdead_0000;
                            context.uc_mcontext.regs.fill(0xface);
                            context.uc_mcontext.pstate = NZCV;
                            // set_signal_return requires a kernel FPSIMD record.
                            let reserved = unsafe {
                                &mut (*core::ptr::from_mut(&mut context.uc_mcontext)
                                    .cast::<litebox_common_linux::signal::aarch64::Sigcontext>())
                                .__reserved
                            };
                            reserved[..4].copy_from_slice(&0x4650_8001u32.to_ne_bytes());
                            reserved[4..8].copy_from_slice(&528u32.to_ne_bytes());
                            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
                            info.si_code = libc::SI_USER;
                            arch::clear_interrupt();
                            unsafe {
                                if interrupt {
                                    dispatch_interrupt(
                                        crate::INTERRUPT_SIGNAL_NUMBER.load(Ordering::Relaxed),
                                        &mut info,
                                        &mut context,
                                        1,
                                        TP2,
                                    );
                                } else {
                                    dispatch_exception(
                                        libc::SIGSEGV,
                                        &mut info,
                                        &mut context,
                                        1,
                                        TP2,
                                    );
                                    assert_eq!(info.si_errno, 1, "{pc:#x}");
                                }
                            }
                            assert_eq!(regs.regs, before.regs, "{pc:#x}");
                            assert_eq!((regs.pc, regs.sp), (before.pc, before.sp), "{pc:#x}");
                            assert_eq!(get_guest_thread_pointer(), TP1, "{pc:#x}");
                            let saved = platform.get_guest_vector_state();
                            assert_eq!(saved.vregs(), vectors().vregs(), "{pc:#x}");
                            assert_eq!(
                                (saved.fpsr(), saved.fpcr()),
                                (vectors().fpsr(), vectors().fpcr()),
                                "{pc:#x}"
                            );
                            assert_eq!(context.uc_mcontext.sp, 0xdead_0000, "{pc:#x}");
                            assert_eq!(context.uc_mcontext.pstate, NZCV, "{pc:#x}");
                            if redirect {
                                assert_eq!(context.uc_mcontext.regs[..4], [0; 4], "{pc:#x}");
                                assert_eq!(context.uc_mcontext.regs[4..], [0xface; 27], "{pc:#x}");
                            } else {
                                assert_eq!(context.uc_mcontext.regs, [0xface; 31], "{pc:#x}");
                            }
                            assert_eq!(
                                usize::try_from(context.uc_mcontext.pc).unwrap(),
                                if redirect {
                                    arch::interrupt_callback as *const () as usize
                                } else {
                                    pc
                                }
                            );
                            assert_eq!(
                                unsafe { ((block + tls_offset::INTERRUPT) as *const u8).read() },
                                u8::from(interrupt && !arch::in_syscall_callback_prologue(pc)),
                                "{pc:#x}"
                            );
                        }
                    }
                }
                unsafe { ((block + tls_offset::GUEST_CONTEXT_TOP) as *mut usize).write(0) };
            },
        );
    }

    #[test]
    fn registration_is_thread_bound() {
        // Type inference is ambiguous if either auto trait becomes implemented.
        trait AmbiguousIfSendOrSync<A> {
            fn check() {}
        }
        impl<T: ?Sized> AmbiguousIfSendOrSync<()> for T {}
        impl<T: ?Sized + Send> AmbiguousIfSendOrSync<u8> for T {}
        impl<T: ?Sized + Sync> AmbiguousIfSendOrSync<u16> for T {}
        let _ = <Registration as AmbiguousIfSendOrSync<_>>::check;
    }

    #[unsafe(naked)]
    unsafe extern "C" fn callback_with_unknown_tp(_tp: usize) -> ! {
        core::arch::naked_asm!("sub sp, sp, #32", "msr tpidr_el0, x0", "b syscall_callback",);
    }

    #[test]
    fn callback_invalid_slot_fails_with_tls_independent_diagnostic() {
        const NAME: &str = "arch::aarch64_pacga::tests::callback_invalid_slot_fails_with_tls_independent_diagnostic";
        const STATE: &str = "LITEBOX_TEST_CALLBACK_INVALID_SLOT";
        if let Ok(state) = std::env::var(STATE) {
            let index = (fingerprint() >> INDEX_SHIFT) as usize;
            let entry = &litebox_pacga_threads[index];
            entry.tid.store(
                match state.as_str() {
                    "missing" => 0,
                    "claimed" => CLAIMED,
                    "null_tp" => 1,
                    _ => panic!("unknown test state"),
                },
                Ordering::Release,
            );
            entry.host_tp.store(0, Ordering::Relaxed);
            // SAFETY: deliberately violates the callback protocol; must exit with
            // no compiled code or libc executing under the unmapped guest TP.
            unsafe { callback_with_unknown_tp(TP1) };
        }
        for state in ["missing", "claimed", "null_tp"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(STATE, state)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(CALLBACK_FAILURE_STATUS),
                "{output:?}"
            );
            assert!(
                output.stderr.ends_with(CALLBACK_FAILURE_MESSAGE),
                "{output:?}"
            );
        }
    }

    #[test]
    fn synchronous_memory_fault_in_native_transition_remains_fatal() {
        isolated(
            "synchronous_memory_fault_in_native_transition_remains_fatal",
            || {
                // Linux's SEGV_MAPERR is not exposed by libc on this target.
                const SEGV_MAPERR: i32 = 1;
                crate::LinuxUserland::new();
                for pc in [
                    interrupt_entry as *const () as u64,
                    arch::syscall_callback as *const () as u64,
                ] {
                    for (signal, code) in [
                        (libc::SIGSEGV, SEGV_MAPERR),
                        (libc::SIGBUS, libc::BUS_ADRERR),
                    ] {
                        // SAFETY: fork-like clone in an isolated test; the child uses
                        // raw fatal syscalls and never unwinds the copied Rust stack.
                        let child = unsafe {
                            syscalls::syscall5(
                                syscalls::Sysno::clone,
                                libc::SIGCHLD as usize,
                                0,
                                0,
                                0,
                                0,
                            )
                        }
                        .unwrap();
                        if child == 0 {
                            let mut context: libc::ucontext_t = unsafe { core::mem::zeroed() };
                            context.uc_mcontext.pc = pc;
                            let mut info: libc::siginfo_t = unsafe { core::mem::zeroed() };
                            info.si_code = code;
                            unsafe {
                                dispatch_exception(signal, &mut info, &mut context, 1, TP2);
                                libc::_exit(12);
                            }
                        }
                        let child = i32::try_from(child).unwrap();
                        let mut status = 0;
                        assert_eq!(unsafe { libc::waitpid(child, &raw mut status, 0) }, child);
                        assert!(libc::WIFSIGNALED(status), "unexpected status {status}");
                        assert!(matches!(
                            libc::WTERMSIG(status),
                            libc::SIGABRT | libc::SIGKILL
                        ));
                    }
                }
            },
        );
    }
}
