#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::host::per_cpu_variables::{
    with_per_cpu_variables, with_per_cpu_variables_mut,
};
use litebox_platform_lvbs::mshv::vsm_intercept::vsm_handle_intercept;
use litebox_platform_lvbs::mshv::vtl_switch::{
    VtlEntryReason, load_vtl_state, save_vtl0_state, save_vtl1_state, vtl_return, vtlcall_dispatch,
};
use litebox_platform_lvbs::mshv::{HV_VTL_NORMAL, HV_VTL_SECURE, VsmFunction};
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, instrs::hlt_loop, interrupts},
    debug_serial_println,
    host::{
        bootparam::get_vtl1_memory_info,
        per_cpu_variables::{KernelTlsOffset, allocate_per_cpu_variables},
    },
    mm::MemoryProvider,
    mshv::{
        hvcall,
        vtl1_mem_layout::{
            PAGE_SIZE, VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE, VTL1_PML4E_PAGE,
            VTL1_PRE_POPULATED_MEMORY_SIZE, get_heap_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn init() -> Option<&'static Platform> {
    let mut ret: Option<&'static Platform> = None;

    if get_core_id() == 0 {
        if let Ok((start, size)) = get_vtl1_memory_info() {
            let vtl1_start = x86_64::PhysAddr::new(start);
            let vtl1_end = x86_64::PhysAddr::new(start + size);

            // Add a small range of mapped memory to the global allocator for populating the kernel page table.
            // `VTL1_INIT_HEAP_START_PAGE` and `VTL1_INIT_HEP_SIZE` specify a physical address range which is
            // not used by the VTL1 kernel.
            let mem_fill_start = usize::try_from(Platform::pa_to_va(vtl1_start).as_u64()).unwrap()
                + VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE;
            let mem_fill_size = VTL1_INIT_HEAP_SIZE;
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            // Add remaining mapped but non-used memory pages (between `get_heap_start_address()` and
            // `vtl1_start + VTL1_PRE_POPULATED_MEMORY_SIZE`) to the global allocator.
            let mem_fill_start = usize::try_from(get_heap_start_address()).unwrap();
            let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE
                - usize::try_from(get_heap_start_address() - start).unwrap();
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            let pml4_table_addr = vtl1_start + u64::try_from(PAGE_SIZE * VTL1_PML4E_PAGE).unwrap();
            let platform = Platform::new(pml4_table_addr, vtl1_start, vtl1_end);
            ret = Some(platform);

            // Add the rest of the VTL1 memory to the global allocator once they are mapped to the kernel page table.
            let mem_fill_start = mem_fill_start + mem_fill_size;
            let mem_fill_size = usize::try_from(
                size - (u64::try_from(mem_fill_start).unwrap()
                    - Platform::pa_to_va(vtl1_start).as_u64()),
            )
            .unwrap();
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            allocate_per_cpu_variables();
        } else {
            panic!("Failed to get memory info");
        }
    }

    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
    gdt::init();
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
    Platform::register_shim(&litebox_shim_optee::OpteeShim);

    ret
}

pub fn run(platform: Option<&'static Platform>) -> ! {
    if let Some(platform) = platform {
        litebox_platform_lvbs::set_platform_low(platform);
    }

    let stack_top = with_per_cpu_variables(|pcv| pcv.kernel_stack_top());
    let stack_top = stack_top & !0xf;
    unsafe {
        core::arch::asm!(
            "mov gs:[{kernel_sp_offset}], {stack_top}",
            stack_top = in(reg) stack_top,
            kernel_sp_offset = const {KernelTlsOffset::KernelStackPtr as usize},
            options(nostack, preserves_flags),
        );
    }

    // This is a dummy call to satisfy load_vtl0_state() with reasonable register values.
    // We do not save VTL0 registers during VTL1 initialization.
    unsafe {
        save_vtl0_state();
    }

    unsafe { vtl_switch_loop_asm() }
}

#[unsafe(naked)]
unsafe extern "C" fn vtl_switch_loop_asm() -> ! {
    core::arch::naked_asm!(
        "1:",
        "call {loop_body}",
        "mov rsp, gs:[{kernel_sp_offset}]",
        "jmp 1b",
        loop_body = sym vtl_switch_loop_body,
        kernel_sp_offset = const {KernelTlsOffset::KernelStackPtr as usize},
    );
}

fn vtl_switch_loop_body() {
    unsafe {
        save_vtl1_state();
        load_vtl_state(HV_VTL_NORMAL);
    }

    vtl_return();

    // *** This is where VTL1 starts to execute code (i.e., VTL0-to-VTL1 switch lands here) ***

    unsafe {
        save_vtl0_state();
        load_vtl_state(HV_VTL_SECURE);
    }

    // Since we do not know whether the VTL0 kernel saves its extended states (e.g., if a VTL switch
    // is due to memory or register access violation, the VTL0 kernel might not have saved
    // its states), we conservatively save and restore its extended states on every VTL switch.
    with_per_cpu_variables_mut(|per_cpu_variables| {
        per_cpu_variables.save_extended_states(HV_VTL_NORMAL);
    });

    let reason = with_per_cpu_variables(|per_cpu_variables| unsafe {
        (*per_cpu_variables.hv_vp_assist_page_as_ptr()).vtl_entry_reason
    });
    match VtlEntryReason::try_from(reason).unwrap_or(VtlEntryReason::Unknown) {
        #[allow(clippy::cast_sign_loss)]
        VtlEntryReason::VtlCall => {
            let params = with_per_cpu_variables(|per_cpu_variables| {
                per_cpu_variables.vtl0_state.get_vtlcall_params()
            });
            if VsmFunction::try_from(u32::try_from(params[0]).unwrap_or(u32::MAX))
                .unwrap_or(VsmFunction::Unknown)
                == VsmFunction::Unknown
            {
                todo!("unknown function ID = {:#x}", params[0]);
            } else {
                let result = vtlcall_dispatch(&params);
                with_per_cpu_variables_mut(|per_cpu_variables| {
                    per_cpu_variables.set_vtl_return_value(result as u64);
                });
            }
        }
        VtlEntryReason::Interrupt => {
            vsm_handle_intercept();
        }
        VtlEntryReason::Unknown => {}
    }

    with_per_cpu_variables(|per_cpu_variables| {
        per_cpu_variables.restore_extended_states(HV_VTL_NORMAL);
    });
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
