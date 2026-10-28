// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-owned TPIDR_EL0 with rewritten guest accesses to a fixed TLS slot.

use super::tls_offset;

pub(super) struct TlsState;

pub(super) const RESERVED_CPU_FEATURES: litebox::arch::aarch64::CpuFeatures =
    litebox::arch::aarch64::CpuFeatures::empty();

macro_rules! enter_host_tp {
    () => {
        "// host TP is already installed; guest TP stays in its TLS slot (+{GUEST_TP})\n"
    };
}

pub(super) use enter_host_tp;

macro_rules! enter_guest_tp {
    ($reg:literal) => {
        "// guest TP stays in its TLS slot (+{GUEST_TP})\n"
    };
}

pub(super) use enter_guest_tp;

/// Byte offset of this thread's `guest_thread_pointer` slot from the thread
/// pointer (TP) — `TPIDR_EL0` — as fixed by this binary's link.
///
/// The loader patches this into every rewritten guest binary's thread-pointer
/// gates. The linker decides it per embedder, but it is the same on every
/// thread.
///
/// # Panics
///
/// Panics if the offset is not one a gate can be patched to reach.
fn guest_thread_pointer_tp_offset() -> u16 {
    let offset = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER;
    u16::try_from(offset)
        .ok()
        .filter(|off| litebox_trampoline::aarch64::is_patchable_guest_tpidr_offset(*off))
        .expect(
            "guest_thread_pointer must sit at a thread-pointer offset a rewriter gate can reach",
        )
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "Both TP modes share this interface."
)]
pub(crate) fn guest_thread_pointer_offset() -> Option<usize> {
    Some(guest_thread_pointer_tp_offset().into())
}

pub(super) fn assert_tls_placement() {
    let _ = guest_thread_pointer_tp_offset();
    let guest_tp = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER;
    let guest_x18 = tprel_offset!(litebox_tls_block) + tls_offset::GUEST_X18;
    assert_eq!(
        guest_x18.checked_sub(guest_tp),
        Some(litebox_trampoline::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP),
    );
    assert!(guest_x18.is_multiple_of(8) && u16::try_from(guest_x18).is_ok());
    #[cfg(feature = "aarch64_virtualize_x18")]
    assert!(
        u16::try_from(guest_x18)
            .is_ok_and(litebox_trampoline::aarch64::is_patchable_guest_x18_offset)
    );
}

const _: () = assert!(
    tls_offset::GUEST_X18 - tls_offset::GUEST_THREAD_POINTER
        == litebox_trampoline::aarch64::GUEST_X18_OFFSET_FROM_GUEST_TP
);

pub(crate) struct Registration;

impl Registration {
    #[inline]
    pub(crate) fn enter() -> Self {
        Self
    }
}

#[inline]
pub(crate) unsafe fn reset_after_fork() {}

#[inline]
pub(crate) fn add_seccomp_rules(_rules: &mut Vec<(i64, Vec<seccompiler::SeccompRule>)>) {}

#[derive(Clone, Copy)]
pub(crate) struct SignalEntry;

#[expect(clippy::unused_self, reason = "Both TP modes share this interface.")]
impl SignalEntry {
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self
    }

    #[inline]
    pub(crate) fn in_exception_prologue(_pc: usize) -> bool {
        false
    }

    #[inline]
    pub(crate) fn capture_guest_tp(self, _pc: usize) {}

    #[inline]
    pub(crate) fn take_guest(self) -> Option<*mut litebox_common_linux::PtRegs> {
        super::signal_handler_take_guest(None)
    }

    #[inline]
    pub(crate) fn take_interrupted_guest(
        self,
        _pc: usize,
    ) -> Option<*mut litebox_common_linux::PtRegs> {
        self.take_guest()
    }
}

pub(crate) unsafe extern "C" fn exception_entry(
    signal: i32,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // SAFETY: caller supplies kernel signal arguments with host TP installed.
    unsafe { super::super::exception_signal_handler(signal, info, context, SignalEntry) };
}

pub(crate) unsafe extern "C" fn interrupt_entry(
    signal: i32,
    info: &mut libc::siginfo_t,
    context: &mut libc::ucontext_t,
) {
    // SAFETY: caller supplies kernel signal arguments with host TP installed.
    unsafe { super::super::interrupt_signal_handler(signal, info, context, SignalEntry) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinuxUserland, arch::tests::gate_bytes};
    use litebox::platform::SystemInfoProvider as _;
    use litebox_trampoline::aarch64::{GateMetadata, gate::GateInstance};

    #[test]
    fn test_gate_patching_lands_in_the_runtime_tls_block() {
        const IMM12_SHIFT: u32 = 10;
        const IMM12_MASK: u32 = 0x003F_FC00;
        const ALIGN: u16 = litebox_trampoline::aarch64::GUEST_TPIDR_OFFSET_ALIGN;

        let (_, mut tramp) = gate_bytes(
            GateInstance::new(GateMetadata::MrsTpidr { destination: 9 }, 0x1004),
            0x400000,
        );
        assert_eq!(
            litebox_trampoline::aarch64::find_guest_tpidr_placeholder(&tramp),
            Some(16 + 4),
            "the emitted gate must be in the unpatched state, or everything below \
             passes vacuously"
        );

        let platform = LinuxUserland::new();
        let offset = platform.guest_thread_pointer_offset().expect(
            "gated TP mode must supply a guest thread-pointer offset; without one the \
             loader leaves every gate on the placeholder, which does not fault",
        );
        let offset = u16::try_from(offset).expect("the guest slot must sit within a gate's reach");
        assert_eq!(
            litebox_trampoline::aarch64::finalize_trampoline_gates(&mut tramp, offset).unwrap(),
            1
        );
        assert_eq!(
            litebox_trampoline::aarch64::find_guest_tpidr_placeholder(&tramp),
            None,
            "no gate may still hold the placeholder once the loader has staged the trampoline"
        );
        let classified = litebox_trampoline::aarch64::classify_gate_pc(&tramp, 0x400000, 0x400010)
            .expect("finalized emitted MRS slot must validate");
        assert_eq!(classified.slot_offset(), 16);
        assert!(matches!(
            classified.metadata(),
            litebox_trampoline::aarch64::GateMetadata::MrsTpidr { destination: 9, .. }
        ));

        let patched = u32::from_le_bytes(tramp[16 + 4..16 + 8].try_into().unwrap());
        let gate_offset = ((patched & IMM12_MASK) >> IMM12_SHIFT) as usize * usize::from(ALIGN);
        let tp: usize;
        // SAFETY: reads the thread pointer; touches no memory.
        unsafe {
            core::arch::asm!(
                "mrs {tp}, tpidr_el0",
                tp = out(reg) tp,
                options(nomem, nostack, preserves_flags)
            );
        }
        let gate_target = tp + gate_offset;

        // Compared against the slot's address as the *linker* resolves it, so
        // this is an independent check of the number rather than a restatement
        // of it.
        assert_eq!(
            gate_target,
            tp + tprel_offset!(litebox_tls_block) + tls_offset::GUEST_THREAD_POINTER,
            "a patched gate must dereference this thread's own `guest_thread_pointer` slot"
        );

        let block = tp + tprel_offset!(litebox_tls_block);
        let block_end = block + core::mem::size_of::<super::super::TlsBlock>();
        assert!(
            (block..block_end).contains(&gate_target),
            "gate dereferences {gate_target:#x}, outside the runtime TLS control block \
             {block:#x}..{block_end:#x}"
        );
    }
}
