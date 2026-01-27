// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::{enable_extended_states, enable_fsgsbase, get_core_id, instrs::hlt_loop},
    host::{
        bootparam::parse_boot_info,
        per_cpu_variables::{PerCpuVariablesAsm, init_per_cpu_variables},
    },
    mm::MemoryProvider,
    serial_println,
};
use litebox_platform_multiplex::Platform;

/// ELF64 relocation entry
#[repr(C)]
struct Elf64Rela {
    offset: u64,
    info: u64,
    addend: i64,
}

const R_X86_64_RELATIVE: u64 = 8;

/// Apply ELF relocations to support position-independent execution.
/// This code has NO dependency on absolute addresses - uses only RIP-relative addressing.
///
/// # Safety
/// - Must be called before any absolute addresses are accessed
/// - Must be called exactly once at boot
/// - Requires valid relocation section in the binary
#[inline(never)]
unsafe fn apply_relocations() {
    unsafe extern "C" {
        static _rela_start: u8;
        static _rela_end: u8;
        static _memory_base: u8;
    }

    // Calculate load offset using ONLY position-independent code
    // This works regardless of where we're loaded

    // Get actual runtime address (where we ARE)
    let actual_base: u64;
    unsafe {
        asm!(
            "lea {}, [rip + _memory_base]",
            out(reg) actual_base,
            options(nostack, nomem, preserves_flags)
        );
    }

    // offset = actual_base - expected_base
    // The expected base is 0x0, so offset = actual_base
    let offset = actual_base;

    // Early return if already at expected location
    if offset == 0 {
        return;
    }

    // Get relocation table bounds using RIP-relative addressing
    let rela_start: u64;
    let rela_end: u64;
    unsafe {
        asm!(
            "lea {start}, [rip + _rela_start]",
            "lea {end}, [rip + _rela_end]",
            start = out(reg) rela_start,
            end = out(reg) rela_end,
            options(nostack, nomem, preserves_flags)
        );
    }

    let mut rela_ptr = rela_start as *const Elf64Rela;
    let rela_end_ptr = rela_end as *const Elf64Rela;

    // Process each relocation entry
    while rela_ptr < rela_end_ptr {
        // SAFETY: rela_ptr is within bounds of relocation section
        let rela = unsafe { &*rela_ptr };
        let r_type = rela.info & 0xffffffff;

        // Only handle R_X86_64_RELATIVE relocations
        if r_type == R_X86_64_RELATIVE {
            // Calculate target address: original offset + load offset
            // SAFETY: Target address is valid after offset adjustment
            let target = (offset.wrapping_add(rela.offset)) as *mut u64;
            // SAFETY: Target is within the .rela.dyn section and properly aligned
            unsafe {
                // Relocation calculation: addend + load_offset
                // The casts between signed/unsigned are intentional for ELF relocation math
                #[allow(clippy::cast_possible_wrap)]
                #[allow(clippy::cast_sign_loss)]
                let value = rela.addend.wrapping_add(offset as i64) as u64;
                target.write_volatile(value);
            }
        }

        // SAFETY: Moving to next entry within bounds
        rela_ptr = unsafe { rela_ptr.add(1) };
    }

    // Reclaim rela.dyn section memory to heap after applying relocations
    // These extern statics are defined by the linker script
    let mem_fill_start = &raw const _rela_start as usize;
    let mem_fill_end = &raw const _rela_end as usize;
    let mem_fill_size = mem_fill_end - mem_fill_start;
    unsafe {
        Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
    }
}

#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    let core_id = get_core_id();
    if core_id == 0 {
        unsafe {
            apply_relocations();
        }
    }

    enable_fsgsbase();
    enable_extended_states();
    init_per_cpu_variables();

    unsafe {
        asm!(
            "mov rsp, gs:[{kernel_sp_off}]",
            "call {kernel_main}",
            kernel_sp_off = const { PerCpuVariablesAsm::kernel_stack_ptr_offset() },
            kernel_main = sym kernel_main
        );
    }

    hlt_loop()
}

unsafe extern "C" fn kernel_main() -> ! {
    let core_id = get_core_id();
    if core_id == 0 {
        serial_println!("==============================");
        serial_println!(" Hello from LiteBox for LVBS! ");
        serial_println!("==============================");

        parse_boot_info();
    }

    let platform = litebox_runner_lvbs::init();
    litebox_runner_lvbs::run(platform)
}
