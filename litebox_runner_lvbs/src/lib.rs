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

use litebox_common_optee::{UteeEntryFunc, UteeParams};
use litebox_shim_optee::{
    UteeParamsTyped, optee_command_dispatcher, register_session_id_elf_load_info,
    submit_optee_command,
};
use x86_64::VirtAddr;

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
            litebox_platform_multiplex::set_platform(platform);

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

        litebox_platform_lvbs::set_optee_callback(optee_call);
        litebox_platform_lvbs::set_optee_callback_done(optee_call_done);
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
    vtl_switch_loop_entry(platform)
}

// callback to work around crate dependency issues. Should be removed once
// we finalize our refactoring.
fn optee_call(session_id: u32, func: UteeEntryFunc, cmd_id: u32, params: &UteeParams) {
    static CALL_ONCE: spin::Once<bool> = spin::Once::new();
    CALL_ONCE.call_once(|| {
        let platform = litebox_platform_lvbs::platform_low();
        if let Ok(session_id) = platform.create_userspace() {
            let session_id: u32 = u32::try_from(session_id).expect("invalid session_id");

            // TODO: load TA ELF binary according to an OP-TEE message command
            // we do have ELF loading here due to crate dependency
            let loaded_program = litebox_shim_optee::loader::load_elf_buffer(TA_BINARY).unwrap();
            register_session_id_elf_load_info(session_id, loaded_program);
            platform
                .save_user_context(
                    VirtAddr::new(u64::try_from(loaded_program.entry_point).unwrap()),
                    VirtAddr::new(u64::try_from(loaded_program.stack_base).unwrap()),
                    x86_64::registers::rflags::RFlags::INTERRUPT_FLAG,
                )
                .expect("Failed to save user context");
        } else {
            panic!("Failed to create userspace");
        }
        true
    });

    // TODO: create a VSM function and do the below within that function
    let mut params_typed = [const { UteeParamsTyped::None }; UteeParamsTyped::TEE_NUM_PARAMS];
    for i in 0..UteeParamsTyped::TEE_NUM_PARAMS {
        params_typed[i] = match params.get_type(i) {
            Ok(ty) => match ty {
                litebox_common_optee::TeeParamType::None => UteeParamsTyped::None,
                litebox_common_optee::TeeParamType::ValueInput => {
                    let Some((a, b)) = params.get_values(i).expect("invalid value input") else {
                        panic!("invalid value input");
                    };
                    UteeParamsTyped::ValueInput {
                        value_a: a,
                        value_b: b,
                    }
                }
                litebox_common_optee::TeeParamType::ValueOutput => UteeParamsTyped::ValueOutput {},
                litebox_common_optee::TeeParamType::ValueInout => {
                    let Some((a, b)) = params.get_values(i).expect("invalid value inout") else {
                        panic!("invalid value inout");
                    };
                    UteeParamsTyped::ValueInout {
                        value_a: a,
                        value_b: b,
                    }
                }
                _ => UteeParamsTyped::None,
            },
            Err(_) => UteeParamsTyped::None,
        };
    }

    submit_optee_command(session_id, func, params_typed, cmd_id);
}

fn optee_call_done(session_id: u32) {
    optee_command_dispatcher(session_id, false);
}

const TA_BINARY: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
