#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts},
    debug_serial_println,
    host::bootparam::get_vtl1_memory_info,
    kernel_context::get_core_id,
    mm::MemoryProvider,
    mshv::{
        hvcall,
        vtl_switch::vtl_switch_loop_entry,
        vtl1_mem_layout::{
            PAGE_SIZE, VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE, VTL1_PML4E_PAGE,
            VTL1_PRE_POPULATED_MEMORY_SIZE, get_heap_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;

use litebox_platform_lvbs::user_context::UserSpaceManagement;

use litebox_common_optee::UteeEntryFunc;
use litebox_shim_optee::{
    UteeParamsTyped, handle_syscall_request, optee_command_dispatcher,
    register_session_id_elf_load_info, submit_optee_command,
};

/// # Panics
///
/// Panics if it failed to enable Hyper-V hypercall
pub fn init() -> Option<&'static Platform> {
    gdt::init();
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();

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
        } else {
            panic!("Failed to get memory info");
        }
    }

    if let Err(e) = hvcall::init() {
        panic!("Err: {:?}", e);
    }
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
    Platform::register_syscall_handler(litebox_shim_optee::handle_syscall_request);

    ret
}

pub fn run(platform: Option<&'static Platform>) -> ! {
    if get_core_id() == 0 {
        if let Some(platform) = platform {
            litebox_platform_multiplex::set_platform(platform);
            litebox_platform_lvbs::set_platform_low(platform);
            if let Ok(session_id) = platform.create_userspace() {
                let session_id: u32 = session_id.try_into().unwrap();

                let loaded_program =
                    litebox_shim_optee::loader::load_elf_buffer(TA_BINARY).unwrap();
                register_session_id_elf_load_info(session_id, loaded_program);

                let params = [
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                ];
                submit_optee_command(session_id, UteeEntryFunc::OpenSession, params, 0);

                let params = [
                    UteeParamsTyped::ValueInout {
                        value_a: 100,
                        value_b: 0,
                    },
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                ];
                submit_optee_command(session_id, UteeEntryFunc::InvokeCommand, params, 0);

                let params = [
                    UteeParamsTyped::ValueInout {
                        value_a: 200,
                        value_b: 0,
                    },
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                ];
                submit_optee_command(session_id, UteeEntryFunc::InvokeCommand, params, 1);

                let params = [
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                    UteeParamsTyped::None,
                ];
                submit_optee_command(session_id, UteeEntryFunc::CloseSession, params, 0);

                optee_command_dispatcher(session_id, false);
            } else {
                panic!("Failed to create userspace");
            }
        } else {
            panic!("Failed to get platform");
        };
    }
    vtl_switch_loop_entry(platform)
}

const TA_BINARY: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
