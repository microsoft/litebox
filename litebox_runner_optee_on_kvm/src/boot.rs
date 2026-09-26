// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PVH-only early entry for the QEMU debugging runner. No firmware abstraction.

use litebox_platform_lvbs::KERNEL_OFFSET;
use litebox_runner_optee_on_kvm::memory_map::{ENTRY_PA, HEAP_FLOOR, SCRATCH_PA};

#[repr(C, align(4))]
struct PvhNote {
    namesz: u32,
    descsz: u32,
    kind: u32,
    name: [u8; 4],
    entry: u32,
}
#[used]
#[unsafe(link_section = ".note.Xen")]
static PVH_NOTE: PvhNote = PvhNote {
    namesz: 4,
    descsz: 4,
    kind: 18,
    name: *b"Xen\0",
    entry: 0x200000,
};
const _: () = assert!(ENTRY_PA == 0x200000);
const _: () = assert!(KERNEL_OFFSET & ((1 << 39) - 1) == 0);
const _: () = assert!(HEAP_FLOOR == SCRATCH_PA + 0x80000);

core::arch::global_asm!(
    include_str!("boot.S"),
    entry = const ENTRY_PA,
    scratch = const SCRATCH_PA,
    kernel_offset = const KERNEL_OFFSET,
    kernel_slot = const (KERNEL_OFFSET >> 39) & 0x1ff,
    rust_entry = sym crate::guest::early_entry,
);

unsafe extern "C" {
    static _text_start: u8;
    static _text_end: u8;
}

pub fn text_physical_range() -> core::ops::Range<u64> {
    (&raw const _text_start as u64 - KERNEL_OFFSET)..(&raw const _text_end as u64 - KERNEL_OFFSET)
}

pub fn start_info_pa() -> u64 {
    // SAFETY: the boot stub stored EBX here before entering Rust. The scratch
    // region is reserved and mapped by the stub; no AP has been started.
    unsafe { ((KERNEL_OFFSET + SCRATCH_PA + 0x3030) as *const u64).read() }
}

#[repr(C)]
struct Rela {
    offset: u64,
    info: u64,
    addend: u64,
}

/// Apply image-relative relocations before accessing statics or vtables.
/// No formatting/panic machinery may be used until this has finished.
///
/// # Safety
/// Call exactly once from the high alias, with the ELF image and targets still
/// writable under the temporary map. The linker starts at zero, so link-time
/// addresses equal physical addresses; the only load bias is KERNEL_OFFSET.
#[inline(never)]
pub unsafe fn relocate() {
    let begin: u64;
    let end: u64;
    let image_end: u64;
    unsafe {
        core::arch::asm!(
            "lea {begin}, [rip + _rela_start]",
            "lea {end}, [rip + _rela_end]",
            "lea {image_end}, [rip + _image_end]",
            begin = out(reg) begin, end = out(reg) end, image_end = out(reg) image_end,
            options(nostack, nomem, preserves_flags),
        );
    }
    let mut at = begin;
    if end < begin || !(end - begin).is_multiple_of(size_of::<Rela>() as u64) {
        crate::guest::exit(false);
    }
    while at < end {
        // SAFETY: linker-emitted, aligned RELA records in the early mapping.
        let rela = unsafe { &*(at as *const Rela) };
        let target = KERNEL_OFFSET.wrapping_add(rela.offset);
        if rela.info != 8
            || !target.is_multiple_of(8)
            || rela.offset < ENTRY_PA
            || target > image_end - 8
            || target < KERNEL_OFFSET + ENTRY_PA
        {
            crate::guest::exit(false);
        }
        // ELF relocation arithmetic is modulo 2^64, including signed addends.
        unsafe {
            (target as *mut u64).write_volatile(KERNEL_OFFSET.wrapping_add(rela.addend));
        }
        at += size_of::<Rela>() as u64;
    }
}
