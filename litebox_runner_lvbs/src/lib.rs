#![no_std]

use core::panic::PanicInfo;
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, instrs::hlt_loop, interrupts},
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::allocate_per_cpu_variables},
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
    vtl_switch_loop_entry(platform)
}

// Tentative OP-TEE message handler upcall implementation.
// This will be revised once the upcall interface is finalized.
// NOTE: This function doesn't work because `run_thread` is not ready.
// It is okay to remove this function in this PR and add it in a follow-up PR.
use litebox::platform::{RawConstPointer, RawMutPointer};
use litebox_common_optee::{
    LdelfArg, OpteeMessageCommand, OpteeMsgArg, OpteeSmcArgs, OpteeSmcReturn, TeeIdentity,
    TeeLogin, TeeUuid, UteeEntryFunc, UteeParamOwned, UteeParams,
};
use litebox_shim_optee::loader::ElfLoadInfo;
use litebox_shim_optee::msg_handler::{
    decode_ta_request, handle_optee_msg_arg, handle_optee_smc_args,
    prepare_for_return_to_normal_world,
};
use litebox_shim_optee::ptr::{NormalWorldConstPtr, NormalWorldMutPtr};
#[expect(dead_code)]
fn optee_msg_handler_upcall(smc_args_addr: usize) -> Result<OpteeSmcArgs, OpteeSmcReturn> {
    let smc_args_ptr = NormalWorldConstPtr::<OpteeSmcArgs>::from_usize(smc_args_addr);
    let mut smc_args = unsafe { smc_args_ptr.read_at_offset(0) }
        .unwrap()
        .into_owned();
    let msg_arg_phys_addr = smc_args.optee_msg_arg_phys_addr()?;
    let (res, msg_arg) = handle_optee_smc_args(&mut smc_args)?;
    if let Some(mut msg_arg) = msg_arg {
        match msg_arg.cmd {
            OpteeMessageCommand::OpenSession
            | OpteeMessageCommand::InvokeCommand
            | OpteeMessageCommand::CloseSession => {
                let Ok(ta_req_info) = decode_ta_request(&msg_arg) else {
                    return Err(OpteeSmcReturn::EBadCmd);
                };

                let params = [const { UteeParamOwned::None }; UteeParamOwned::TEE_NUM_PARAMS];
                if ta_req_info.entry_func == UteeEntryFunc::OpenSession {
                    let _litebox = litebox_shim_optee::init_session(
                        &TeeUuid::default(),
                        &TeeIdentity {
                            login: TeeLogin::User,
                            uuid: TeeUuid::default(),
                        },
                        Some(TA_BINARY), // TODO: replace this with UUID-based TA loading
                    );

                    let ldelf_info = litebox_shim_optee::loader::load_elf_buffer(LDELF_BINARY)
                        .expect("Failed to load ldelf");
                    let Some(ldelf_arg_address) = ldelf_info.ldelf_arg_address else {
                        panic!("ldelf_arg_address not found");
                    };
                    let ldelf_arg = LdelfArg::new(); // TODO: set TA UUID

                    let stack = litebox_shim_optee::loader::init_ldelf_stack(
                        Some(ldelf_info.stack_base),
                        &ldelf_arg,
                    )
                    .expect("Failed to initialize stack for ldelf");
                    let mut _pt_regs =
                        litebox_shim_optee::loader::prepare_ldelf_registers(&ldelf_info, &stack);
                    // TODO: run_thread

                    // Note: `ldelf` allocates stack (returned via `stack_ptr`) but we don't use it here.
                    // Need to revisit this to see whether the stack is large enough for our use cases (e.g.,
                    // copy owned data through stack to minimize TOCTTOU threats).
                    let ldelf_arg_out = unsafe { &*(ldelf_arg_address as *const LdelfArg) };
                    let entry_func = usize::try_from(ldelf_arg_out.entry_func).unwrap();

                    litebox_shim_optee::set_ta_loaded();

                    litebox_shim_optee::loader::allocate_guest_tls(None)
                        .expect("Failed to allocate TLS");

                    // TODO: maintain this ta load info in a global data structure
                    let ta_info = ElfLoadInfo {
                        entry_point: entry_func,
                        stack_base: ldelf_info.stack_base,
                        params_address: ldelf_info.params_address,
                        ldelf_arg_address: None,
                    };

                    // In OP-TEE TA, each command invocation is like (re)starting the TA with a new stack with
                    // loaded binary and heap. In that sense, we can create (and destroy) a stack
                    // for each command freely.
                    let stack = litebox_shim_optee::loader::init_stack(
                        Some(ta_info.stack_base),
                        params.as_slice(),
                    )
                    .expect("Failed to initialize stack with parameters");
                    let mut _pt_regs = litebox_shim_optee::loader::prepare_registers(
                        &ta_info,
                        &stack,
                        litebox_shim_optee::get_session_id(),
                        ta_req_info.entry_func as u32,
                        None,
                    );

                    // TODO: run_thread

                    // SAFETY
                    // We assume that `ta_info.params_address` is a valid pointer to `UteeParams`.
                    let ta_params = unsafe { *(ta_info.params_address as *const UteeParams) };

                    prepare_for_return_to_normal_world(&ta_params, &ta_req_info, &mut msg_arg)?;

                    let ptr = NormalWorldMutPtr::<OpteeMsgArg>::from_usize(
                        usize::try_from(msg_arg_phys_addr).unwrap(),
                    );
                    let _ = unsafe { ptr.write_at_offset(0, msg_arg) };
                } else {
                    // retrieve `ta_info` from global data structure
                    todo!()
                }
                Ok(res.into())
            }
            _ => {
                handle_optee_msg_arg(&msg_arg)?;
                Ok(res.into())
            }
        }
    } else {
        Ok(res.into())
    }
}

const TA_BINARY: &[u8] = &[0u8; 0];
const LDELF_BINARY: &[u8] = &[0u8; 0];

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    hlt_loop()
}
