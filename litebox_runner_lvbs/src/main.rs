#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use core::arch::asm;
use litebox_platform_lvbs::{
    arch::{enable_extended_states, enable_fsgsbase, get_core_id, instrs::{hlt_loop, wrmsr}},
    host::{bootparam::parse_boot_info, per_cpu_variables::with_per_cpu_variables},
    mshv::{HV_X64_MSR_GUEST_OS_ID},
    serial_println,
};

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
    asm!(
        "lea {}, [rip + _memory_base]",
        out(reg) actual_base,
        options(nostack, nomem, preserves_flags)
    );
    
    // Get link-time address (where linker EXPECTED us to be)
    // SAFETY: This is also position-independent - it's just the address
    // the linker embedded in the relocation entries themselves
 //   let expected_base: u64;
 //   asm!(
 //       "lea {}, _memory_base",
 //       out(reg) expected_base,
 //       options(nostack, nomem, preserves_flags)
 //   );
    // Get link-time address from linker script
    const EXPECTED_BASE: u64 = 0x8000000;
    let expected_base = EXPECTED_BASE;
    
    let offset = actual_base.wrapping_sub(expected_base);
    
    // Early return if already at expected location
    if offset == 0 {
        return;
    }

    // Get relocation table bounds using RIP-relative addressing
    let rela_start: u64;
    let rela_end: u64;
    asm!(
        "lea {start}, [rip + _rela_start]",
        "lea {end}, [rip + _rela_end]",
        start = out(reg) rela_start,
        end = out(reg) rela_end,
        options(nostack, nomem, preserves_flags)
    );
    
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
            let target = (rela.offset.wrapping_add(offset)) as *mut u64;
            unsafe {
                target.write_volatile(
                    (rela.addend as u64).wrapping_add(offset)
                );
            }
        }
        
        // SAFETY: Moving to next entry within bounds
        rela_ptr = unsafe { rela_ptr.add(1) };
    }
}
#[expect(clippy::inline_always)]
#[inline(always)]
fn my_vtl_return() {
    wrmsr(HV_X64_MSR_GUEST_OS_ID, 0x818000040f120000);
    unsafe {
        asm!(
            "xor rax, rax",
            "mov rcx, 0x12",
            "vmcall",
         );
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
    let stack_top = with_per_cpu_variables(
        litebox_platform_lvbs::host::per_cpu_variables::PerCpuVariables::kernel_stack_top,
    );

    unsafe {
        asm!(
            "mov rsp, rax",
            "and rsp, -16",
            "call {kernel_main}",
            in("rax") stack_top, kernel_main = sym kernel_main
        );
    }

    hlt_loop()
}

unsafe extern "C" fn kernel_main() -> ! {
    let core_id = get_core_id();
    if core_id == 0 {
        serial_println!("==============================");
        serial_println!(" Hello from LiteBox for LVBS with relocation! ");
        serial_println!("==============================");

        parse_boot_info();
    }
    let platform = litebox_runner_lvbs::init();
    litebox_runner_lvbs::run(platform)
}
