#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]

use bootloader::{BootInfo, bootinfo::MemoryRegionType, entry_point};
use core::panic::PanicInfo;
use litebox_common_optee::{TeeIdentity, TeeLogin, TeeUuid, UteeEntryFunc, UteeParamOwned};
use litebox_platform_hypervisor::{
    arch::{enable_extended_states, enable_fsgsbase, gdt, instrs::hlt_loop, interrupts},
    debug_serial_println,
    mm::MemoryProvider,
    serial_println,
    user_context::UserSpaceManagement,
};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::loader::ElfLoadInfo;
// use pic8259::ChainedPics;
use x86_64::VirtAddr;

// program 8259 PIC
// const PIC_1_OFFSET: u8 = 32;
// const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;
// static PICS: spin::Mutex<ChainedPics> =
//     spin::Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

entry_point!(kernel_main);

fn kernel_main(bootinfo: &'static BootInfo) -> ! {
    serial_println!("====================================");
    serial_println!(" Hello from LiteBox for Hypervisor! ");
    serial_println!("====================================");

    let phys_mem_offset = VirtAddr::new(bootinfo.physical_memory_offset);
    debug_serial_println!("Physical memory offset: {:#x}", phys_mem_offset.as_u64());

    let memory_map = &bootinfo.memory_map;
    for region in memory_map.iter() {
        if region.region_type == MemoryRegionType::Usable {
            let mem_fill_start =
                usize::try_from(phys_mem_offset.as_u64() + region.range.start_frame_number * 4096)
                    .unwrap();
            let mem_fill_size = usize::try_from(
                (region.range.end_frame_number - region.range.start_frame_number) * 4096,
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
        }
    }

    let l4_table = unsafe { active_level_4_table_addr() };
    debug_serial_println!("L4 table physical Address: {:#x}", l4_table.as_u64());

    let platform = Platform::new(l4_table);
    debug_serial_println!("LiteBox Platform created at {:p}.", platform);

    enable_fsgsbase();
    enable_extended_states();

    gdt::init();
    debug_serial_println!("GDT initialized.");

    interrupts::init_idt();
    debug_serial_println!("IDT initialized.");

    // TODO: enable this once we figure out how to handle timer interrupts (ignore?)
    // unsafe {
    //     PICS.lock().initialize();
    // }
    // x86_64::instructions::interrupts::enable();
    // debug_serial_println!("PIC and interrupts enabled.");

    litebox_platform_multiplex::set_platform(platform);
    litebox_platform_hypervisor::set_platform_low(platform);
    Platform::register_shim(&litebox_shim_optee::OpteeShim);
    debug_serial_println!("OP-TEE Shim registered.");

    if let Ok(session_id) = platform.create_userspace() {
        let loaded_ta = litebox_shim_optee::loader::load_elf_buffer(TA_BINARY).unwrap();
        platform
            .save_user_context(
                VirtAddr::new(u64::try_from(loaded_ta.entry_point).unwrap()),
                VirtAddr::new(u64::try_from(loaded_ta.stack_base).unwrap()),
                x86_64::registers::rflags::RFlags::INTERRUPT_FLAG,
            )
            .expect("Failed to save user context");
        run_ta_with_default_commands(session_id, &loaded_ta);
    }

    hlt_loop()
}

/// This function simply opens and closes a session to the TA to verify that
/// it can be loaded and run. Note that an OP-TEE TA does nothing without
/// a client invoking commands on it.
fn run_ta_with_default_commands(session_id: usize, ta_info: &ElfLoadInfo) {
    for func_id in [UteeEntryFunc::OpenSession, UteeEntryFunc::CloseSession] {
        let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];

        if func_id == UteeEntryFunc::OpenSession {
            let _litebox = litebox_shim_optee::init_session(
                &TeeUuid::default(),
                &TeeIdentity {
                    login: TeeLogin::User,
                    uuid: TeeUuid::default(),
                },
            );

            // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
            // loaded binary and heap. In that sense, we can create (and destroy) a stack
            // for each command freely.
            let stack =
                litebox_shim_optee::loader::init_stack(Some(ta_info.stack_base), params.as_slice())
                    .expect("Failed to initialize stack with parameters");
            // let mut pt_regs = litebox_shim_optee::loader::prepare_registers(
            //     ta_info,
            //     &stack,
            //     litebox_shim_optee::get_session_id(),
            //     func_id as u32,
            //     None,
            // );
            // unsafe { litebox_platform_hypervisor::run_thread(&mut pt_regs) };
            unsafe {
                jump_to_entry_point(
                    0,
                    session_id,
                    ta_info.params_address,
                    0,
                    ta_info.entry_point,
                    stack.get_cur_stack_top(),
                )
            }
        }

        if func_id == UteeEntryFunc::CloseSession {
            litebox_shim_optee::deinit_session();
        }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn jump_to_entry_point(
    func: usize,
    session_id: usize,
    params: usize,
    cmd_id: usize,
    entry_point: usize,
    user_stack_top: usize,
) -> ! {
    // kernel mode
    core::arch::naked_asm!("mov rsp, r9", "jmp r8", "hlt");

    // user mode
    // core::arch::naked_asm!(
    //     "mov rax, cr3",
    //     "mov cr3, rax",
    //     "mov rax, {user_ds}",
    //     "push rax",
    //     "push r9",
    //     "mov rax, {rflags}",
    //     "push rax",
    //     "mov rax, {user_cs}",
    //     "push rax",
    //     "push r8",
    //     "iretq",
    //     "hlt",
    //     user_cs = const 0x2b,
    //     rflags = const 0,
    //     user_ds = const 0x33,
    // );
}

unsafe fn active_level_4_table_addr() -> x86_64::PhysAddr {
    use x86_64::registers::control::Cr3;
    let (level_4_table_frame, _) = Cr3::read();
    level_4_table_frame.start_address()
}

const TA_BINARY: &[u8] =
    include_bytes!("../../litebox_runner_optee_on_linux_userland/tests/hello-ta.elf");

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
