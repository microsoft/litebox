// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::{enable_extended_states, enable_fsgsbase, instrs::hlt_loop, is_bsp},
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

/// BSP entry point. Applies ELF relocations then falls through to common
/// initialisation. Only the BSP must enter via `_start`; APs enter at
/// [`_ap_start`].
#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    unsafe {
        apply_relocations();
    }

    // SAFETY: falls through to the same init path APs use.
    #[expect(clippy::used_underscore_items)]
    unsafe {
        _ap_start()
    }
}

/// AP entry point: Common initialization shared by BSP (after relocations)
/// and all APs. APs are directed here by `init_vtl_ap` via
/// [`get_entry`](litebox_platform_lvbs::mshv::hvcall_vp).
#[expect(clippy::missing_safety_doc)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _ap_start() -> ! {
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
    if is_bsp() {
        serial_println!("==============================");
        serial_println!(" Hello from LiteBox for LVBS! ");
        serial_println!("==============================");

        parse_boot_info();
    }

    let platform = litebox_runner_lvbs::init();
    litebox_runner_lvbs::run(platform)
}
