// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-core `syscall` entry stubs.
//!
//! `syscall` is the one kernel entry with an untrusted RSP and no free
//! register, so it needs an anchor that does not rely on GS (this kernel is
//! gsbase-less, see `PerCpuVariables`). The anchor is the LSTAR MSR itself:
//! it is per-core, so each core points it at its own 32-byte stub in a
//! compile-time `.rept` table. Stub `i` spills user `rax` into
//! `SYSCALL_SLOTS[i]`, loads that core's `PerCpuVariables` pointer into
//! `rax`, and jumps to the shared `syscall_callback`, which then runs fully
//! base-register-relative.
//!
//! The stubs use only RIP-relative addressing (static PC32 relocations), so
//! the table is ordinary shared .text — no runtime codegen, no per-core
//! executable pages, and nothing new for the runner's self-relocation pass
//! (which only handles `R_X86_64_RELATIVE`).

use crate::arch::MAX_CORES;
use crate::host::per_cpu_variables::with_per_cpu_variables;
use core::arch::global_asm;
use core::cell::{Cell, UnsafeCell};
use x86_64::{
    VirtAddr,
    registers::{
        model_specific::{Efer, EferFlags, LStar, SFMask, Star},
        rflags::RFlags,
    },
};

/// Byte stride of one stub in the `syscall_entry_stubs` table.
const SYSCALL_STUB_STRIDE: usize = 32;

/// Per-core syscall entry slot: the stub's `rax` spill cell plus the cached
/// `PerCpuVariables` pointer the stub loads. 64-byte stride (one cache line
/// per core) prevents false sharing on the hot spill store.
#[repr(C, align(64))]
struct SyscallSlot {
    /// User `rax` spilled by this core's stub on every syscall entry.
    rax_spill: UnsafeCell<u64>,
    /// This core's `PerCpuVariables` address, written once at [`init`].
    pcv: Cell<usize>,
    _pad: [u8; 48],
}

const _: () = assert!(size_of::<SyscallSlot>() == 64);
// `syscall_callback` reads the spilled user rax via a single deref of
// `PerCpuVariablesAsm::syscall_slot_ptr`, which relies on `rax_spill` being
// the first field.
const _: () = assert!(core::mem::offset_of!(SyscallSlot, rax_spill) == 0);
const _: () = assert!(core::mem::offset_of!(SyscallSlot, pcv) == 8);

// SAFETY: each slot is written and read only by its owning core (the core
// whose LSTAR points at stub `i` and whose `vp_index()` is `i`).
unsafe impl Sync for SyscallSlot {}

#[allow(clippy::declare_interior_mutable_const)]
const EMPTY_SLOT: SyscallSlot = SyscallSlot {
    rax_spill: UnsafeCell::new(0),
    pcv: Cell::new(0),
    _pad: [0; 48],
};

/// One slot per core, indexed by Hyper-V VP index (8 KiB of .bss).
static SYSCALL_SLOTS: [SyscallSlot; MAX_CORES] = [EMPTY_SLOT; MAX_CORES];

// The stub table: MAX_CORES stubs, 32 bytes apart (19 bytes used). Stub `i`:
//   mov [rip + SYSCALL_SLOTS + i*64], rax     ; spill user rax
//   mov rax, [rip + SYSCALL_SLOTS + i*64 + 8] ; rax := this core's pcv
//   jmp syscall_callback
// The two-instruction window still runs on the (untrusted) user RSP; it is
// interrupt-free for the same reasons today's entry sequence is: SFMASK
// masks IF, and NMI/MCE are never delivered to VTL1.
// `init()` asserts at boot that the emitted table's label-difference size
// matches the SYSCALL_STUB_STRIDE the Rust side uses to program LSTAR
// (the assembler cannot fold the label difference at parse time because of
// the `.balign` fragments, so the check cannot be a `.if`).
global_asm!(
    ".balign 32",
    ".globl syscall_entry_stubs",
    "syscall_entry_stubs:",
    ".set stub_index, 0",
    ".rept {max_cores}",
    ".balign 32",
    "mov qword ptr [rip + {slots} + stub_index * 64], rax",
    "mov rax, qword ptr [rip + {slots} + stub_index * 64 + 8]",
    "jmp syscall_callback",
    ".set stub_index, stub_index + 1",
    ".endr",
    ".balign 32",
    ".globl syscall_entry_stubs_end",
    "syscall_entry_stubs_end:",
    max_cores = const MAX_CORES,
    slots = sym SYSCALL_SLOTS,
);

unsafe extern "C" {
    /// First stub of the table defined in `global_asm!` above.
    fn syscall_entry_stubs();
    /// One-past-the-end label of the stub table.
    fn syscall_entry_stubs_end();
}

/// This function enables 64-bit syscall extensions and sets up the necessary MSRs.
/// It must be called for each core.
///
/// # Panics
///
/// Panics if GDT is not initialized for the current core.
#[cfg(target_arch = "x86_64")]
pub(crate) fn init() {
    // TODO: Revisit this function with PR 566.
    // enable 64-bit syscall/sysret
    let mut efer = Efer::read();
    efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
    unsafe { Efer::write(efer) };

    // Mask some important bits of the FLAGS register.
    //
    // - IF: to block interrupts during syscall handling
    // - DF: to maintain the direction of some instructions like `movs`
    // - AC: to maintain SMAP enforcement active
    // - TF: to prevent kernel-mode single-stepping
    // - NT and IOPL: Defense-in-depth. ring-3 should not be able to affect these bits.
    let rflags = RFlags::INTERRUPT_FLAG
        | RFlags::DIRECTION_FLAG
        | RFlags::ALIGNMENT_CHECK
        | RFlags::TRAP_FLAG
        | RFlags::NESTED_TASK
        | RFlags::IOPL_LOW
        | RFlags::IOPL_HIGH;
    SFMask::write(rflags);

    // Label-difference check: the emitted stub table must match the stride
    // used below to compute each core's LSTAR value.
    assert_eq!(
        syscall_entry_stubs_end as *const () as usize - syscall_entry_stubs as *const () as usize,
        MAX_CORES * SYSCALL_STUB_STRIDE,
        "syscall stub table stride drift"
    );

    // Register this core's slot and point its LSTAR at its own stub.
    let (kernel_cs, user_cs) = with_per_cpu_variables(|per_cpu_variables| {
        let vp_index = per_cpu_variables.vp_index() as usize;
        let slot = &SYSCALL_SLOTS[vp_index];
        slot.pcv
            .set(core::ptr::from_ref(per_cpu_variables) as usize);
        per_cpu_variables
            .asm
            .set_syscall_slot_ptr(core::ptr::from_ref(slot) as usize);
        LStar::write(VirtAddr::new(
            (syscall_entry_stubs as *const () as usize + vp_index * SYSCALL_STUB_STRIDE) as u64,
        ));

        let (kernel_cs, user_cs, _) = per_cpu_variables
            .get_segment_selectors()
            .expect("GDT not initialized for the current core");
        (kernel_cs, user_cs)
    });

    // configure STAR MSR for CS/SS selectors
    unsafe { Star::write_raw(user_cs, kernel_cs) };
}
