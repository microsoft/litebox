// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

extern crate alloc;

use core::{ops::Neg, panic::PanicInfo};
use litebox::{
    mm::linux::PAGE_SIZE,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeSmcArgs, OpteeSmcReturnCode, UteeParams,
};
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, interrupts},
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables::allocate_per_cpu_variables},
    mm::MemoryProvider,
    mshv::{
        NUM_VTLCALL_PARAMS, VsmFunction, hvcall,
        vsm::vsm_dispatch,
        vsm_intercept::raise_vtl0_gp_fault,
        vtl_switch::{vtl_switch, vtl_switch_init},
        vtl1_mem_layout::{
            VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE, VTL1_PML4E_PAGE,
            VTL1_PRE_POPULATED_MEMORY_SIZE, get_heap_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::msg_handler::{
    decode_ta_request, handle_optee_msg_arg, handle_optee_smc_args,
    prepare_for_return_to_normal_world,
};
use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr};
use spin::mutex::SpinMutex;

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
    Platform::enable_syscall_support();

    ret
}

pub fn run(platform: Option<&'static Platform>) -> ! {
    vtl_switch_init(platform);

    let mut return_value: Option<i64> = None;
    loop {
        let params = vtl_switch(return_value);
        return_value = Some(vtlcall_dispatch(&params));
    }
}

/// Dispatch VTL call based on the function ID in params[0] and return the result.
///
/// VTL call is with up to four u64 parameters and returns an i64 result.
/// The first parameter (params[0]) is the VSM function ID to identify the requested service.
/// The remaining parameters (params[1] to params[3]) are function-specific arguments.
///
/// TODO: Consider unified interface signature and naming
/// VTL call is Hyper-V specific. However, in general, there is no fundamental difference
/// between VTL call and TrustZone SMC call, TDX TDCALL, etc.
fn vtlcall_dispatch(params: &[u64; NUM_VTLCALL_PARAMS]) -> i64 {
    let func_id: u32 = params[0].truncate();
    let Ok(func_id) = VsmFunction::try_from(func_id) else {
        return Errno::EINVAL.as_neg().into();
    };
    match func_id {
        VsmFunction::OpteeMessage => {
            let smc_args_pfn = params[1];
            optee_smc_handler_entry(smc_args_pfn)
        }
        _ => vsm_dispatch(func_id, &params[1..]),
    }
}

/// An entry point function to handle OP-TEE SMC call.
fn optee_smc_handler_entry(smc_args_pfn: u64) -> i64 {
    match optee_smc_handler_entry_inner(smc_args_pfn) {
        Ok(res) => res,
        Err(e) => e.as_neg().into(),
    }
}

fn optee_smc_handler_entry_inner(
    smc_args_pfn: u64,
) -> Result<i64, litebox_common_linux::errno::Errno> {
    let smc_args_pfn: usize = smc_args_pfn.truncate();
    let smc_args_addr = smc_args_pfn << litebox_platform_lvbs::mshv::vtl1_mem_layout::PAGE_SHIFT;
    match optee_smc_handler(smc_args_addr) {
        Ok(smc_args_updated) => {
            // Write back the SMC arguments page to normal world memory.
            let mut smc_args_ptr =
                NormalWorldMutPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
                    .map_err(|_| litebox_common_linux::errno::Errno::EINVAL)?;
            // SAFETY: The SMC args are written back to normal world memory.
            unsafe { smc_args_ptr.write_at_offset(0, smc_args_updated) }
                .map_err(|_| litebox_common_linux::errno::Errno::EFAULT)?;
            Ok(0)
        }
        Err(smc_ret) => Err(smc_ret.into()),
    }
}

/// Global state for the loaded TA program.
/// This is needed because InvokeCommand needs access to the TA that was loaded during OpenSession.
struct TaState {
    /// The shim must be kept alive to keep the loaded program's memory mappings valid.
    _shim: litebox_shim_optee::OpteeShim,
    loaded_program: litebox_shim_optee::LoadedProgram,
}

// SAFETY: LVBS VTL1 is single-threaded per-CPU, so there are no concurrent accesses.
// TaState contains only thread-safe types (OpteeShim and LoadedProgram).
unsafe impl Send for TaState {}
// SAFETY: LVBS VTL1 is single-threaded per-CPU, so there are no concurrent accesses.
unsafe impl Sync for TaState {}

/// Persistent TA state that survives CloseSession.
///
/// Currently, we only support a single session, single instance TA since we only
/// supporta single page table. To avoid page table conflicts from re-loading ldelf/TA,
/// we keep the first loaded TA alive and reuse it for all subsequent sessions.
///
/// This is a temporary workaround until proper page table management is implemented
/// (e.g., using `UserSpaceManagement` in `litebox_platform_lvbs`).
///
/// # Future Design: Multi-Instance TA Support
///
/// Our main target is **multi-instance TAs** (without `TA_FLAG_SINGLE_INSTANCE`),
/// where each `OpenSession` creates a new TA instance with its own isolated state.
///
/// To properly support multi-instance TAs, the following changes are needed:
///
/// 1. **Per-session page tables**: Each session (= TA instance) should have its own
///    separate page table (for userspace. kernel space is shared). This provides
///    isolation between concurrent TA instances and allows clean teardown on
///    `CloseSession`.
///
/// 2. **TaInstanceMap**: Use `HashMap<session_id, TaInstance>` to store per-session
///    state. Each `TaInstance` owns its page table.
///
/// 3. **CloseSession cleanup**: On `CloseSession`, unmap all userspace addresses in
///    the session's page table and remove the entry from `TaInstanceMap`. This
///    reclaims memory and allows new sessions to be created without conflicts.
///
/// Note: Single-instance TAs (`TA_FLAG_SINGLE_INSTANCE`) are not currently targeted.
/// If needed in the future, they would require sharing a page table across sessions
/// and reference counting for cleanup.
static PERSISTENT_TA: SpinMutex<Option<TaState>> = SpinMutex::new(None);

/// Handler for OP-TEE SMC calls.
///
/// This function processes SMC calls from the normal world (VTL0) and dispatches them
/// to the appropriate handlers based on the command type.
///
/// For TA requests (OpenSession, InvokeCommand, CloseSession), it uses `decode_ta_request`
/// to extract the TA request information and load/run it using `OpteeShim`.
///
/// # Panics
///
/// Panics if `loaded_program.entrypoints` is `None` when attempting to run the TA.
/// This should not happen in normal operation as `entrypoints` is always `Some` after
/// loading.
fn optee_smc_handler(smc_args_addr: usize) -> Result<OpteeSmcArgs, OpteeSmcReturnCode> {
    let mut smc_args_ptr =
        NormalWorldConstPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)?;
    // SAFETY: The SMC args are read from normal world memory into an owned copy.
    let mut smc_args = unsafe { smc_args_ptr.read_at_offset(0) }?;
    let msg_arg_phys_addr = smc_args.optee_msg_arg_phys_addr()?;
    let smc_result = handle_optee_smc_args(&mut smc_args)?;
    match smc_result {
        litebox_common_optee::OpteeSmcResult::CallWithArg { msg_arg } => {
            let mut msg_arg = *msg_arg;
            debug_serial_println!("OP-TEE SMC with MsgArgs Command: {:?}", msg_arg.cmd);
            match msg_arg.cmd {
                OpteeMessageCommand::OpenSession => {
                    let Ok(ta_req_info) = decode_ta_request(&msg_arg) else {
                        return Err(OpteeSmcReturnCode::EBadCmd);
                    };

                    let func_id = ta_req_info.entry_func;
                    let ta_uuid = ta_req_info.uuid.unwrap_or_default();
                    let params = &ta_req_info.params;

                    // Check if we already have a loaded TA (reuse it to avoid page table conflicts)
                    let persistent_guard = PERSISTENT_TA.lock();
                    let need_load = persistent_guard.is_none();
                    drop(persistent_guard);

                    let (_session_id, params_address) = if need_load {
                        // First time: load ldelf and the TA
                        let shim_builder = litebox_shim_optee::OpteeShimBuilder::new();
                        let shim = shim_builder.build();

                        // TODO: drop `TA_BINARY` usage when we support RPC to load TA from normal world.
                        let mut loaded_program = shim
                            .load_ldelf(LDELF_BINARY, ta_uuid, Some(TA_BINARY), None)
                            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

                        // Run ldelf to load the TA
                        // SAFETY: The context is valid user context from ldelf loading.
                        loaded_program.entrypoints = Some(unsafe {
                            litebox_platform_lvbs::run_thread(
                                loaded_program.entrypoints.take().unwrap(),
                                &mut litebox_common_linux::PtRegs::default(),
                            )
                        });

                        // Load TA context with parameters (no cmd_id for OpenSession)
                        loaded_program
                            .entrypoints
                            .as_ref()
                            .unwrap()
                            .load_ta_context(params.as_slice(), None, func_id as u32, None)
                            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

                        // Run the TA entry function
                        // SAFETY: The context is valid user context from TA context loading.
                        loaded_program.entrypoints = Some(unsafe {
                            litebox_platform_lvbs::reenter_thread(
                                loaded_program.entrypoints.take().unwrap(),
                                &mut litebox_common_linux::PtRegs::default(),
                            )
                        });

                        let session_id = loaded_program
                            .entrypoints
                            .as_ref()
                            .unwrap()
                            .get_session_id();
                        let params_address = loaded_program
                            .params_address
                            .ok_or(OpteeSmcReturnCode::EBadAddr)?;

                        // Store in persistent state to keep it alive across sessions
                        let mut persistent_guard = PERSISTENT_TA.lock();
                        *persistent_guard = Some(TaState {
                            _shim: shim,
                            loaded_program,
                        });

                        (session_id, params_address)
                    } else {
                        let mut persistent_guard = PERSISTENT_TA.lock();
                        let ta_state = persistent_guard
                            .as_mut()
                            .ok_or(OpteeSmcReturnCode::ENotAvail)?;

                        // Load TA context with parameters (no cmd_id for OpenSession)
                        ta_state
                            .loaded_program
                            .entrypoints
                            .as_ref()
                            .unwrap()
                            .load_ta_context(params.as_slice(), None, func_id as u32, None)
                            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

                        // Run the TA entry function
                        // SAFETY: The context is valid user context from TA context loading.
                        ta_state.loaded_program.entrypoints = Some(unsafe {
                            litebox_platform_lvbs::reenter_thread(
                                ta_state.loaded_program.entrypoints.take().unwrap(),
                                &mut litebox_common_linux::PtRegs::default(),
                            )
                        });

                        let session_id = ta_state
                            .loaded_program
                            .entrypoints
                            .as_ref()
                            .unwrap()
                            .get_session_id();
                        let params_address = ta_state
                            .loaded_program
                            .params_address
                            .ok_or(OpteeSmcReturnCode::EBadAddr)?;

                        (session_id, params_address)
                    };

                    // SAFETY: We assume that `params_address` is a valid pointer to `UteeParams`.
                    let ta_params = unsafe { *(params_address as *const UteeParams) };

                    prepare_for_return_to_normal_world(&ta_params, &ta_req_info, &mut msg_arg)?;

                    // Overwrite `msg_arg` back to normal world memory to return value outputs.
                    let mut ptr = NormalWorldMutPtr::<OpteeMsgArgs, PAGE_SIZE>::with_usize(
                        msg_arg_phys_addr.truncate(),
                    )?;
                    // SAFETY: Writing the msg_arg back to normal world memory.
                    unsafe { ptr.write_at_offset(0, msg_arg) }?;

                    Ok(litebox_common_optee::OpteeSmcResult::Generic {
                        status: OpteeSmcReturnCode::Ok,
                    }
                    .into())
                }
                OpteeMessageCommand::InvokeCommand => {
                    let Ok(ta_req_info) = decode_ta_request(&msg_arg) else {
                        return Err(OpteeSmcReturnCode::EBadCmd);
                    };

                    let func_id = ta_req_info.entry_func;
                    let cmd_id = ta_req_info.cmd_id;
                    let params = &ta_req_info.params;

                    // Use the persistent TA (we only support single TA for now)
                    let mut persistent_guard = PERSISTENT_TA.lock();
                    let ta_state = persistent_guard
                        .as_mut()
                        .ok_or(OpteeSmcReturnCode::ENotAvail)?;

                    // Load TA context with parameters and cmd_id
                    ta_state
                        .loaded_program
                        .entrypoints
                        .as_ref()
                        .unwrap()
                        .load_ta_context(params.as_slice(), None, func_id as u32, Some(cmd_id))
                        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

                    // Run the TA entry function
                    // SAFETY: The context is valid user context from TA context loading.
                    ta_state.loaded_program.entrypoints = Some(unsafe {
                        litebox_platform_lvbs::reenter_thread(
                            ta_state.loaded_program.entrypoints.take().unwrap(),
                            &mut litebox_common_linux::PtRegs::default(),
                        )
                    });

                    // SAFETY: We assume that `params_address` is a valid pointer to `UteeParams`.
                    let params_address = ta_state
                        .loaded_program
                        .params_address
                        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
                    let ta_params = unsafe { *(params_address as *const UteeParams) };

                    prepare_for_return_to_normal_world(&ta_params, &ta_req_info, &mut msg_arg)?;

                    // Overwrite `msg_arg` back to normal world memory to return value outputs.
                    let mut ptr = NormalWorldMutPtr::<OpteeMsgArgs, PAGE_SIZE>::with_usize(
                        msg_arg_phys_addr.truncate(),
                    )?;
                    // SAFETY: Writing the msg_arg back to normal world memory.
                    unsafe { ptr.write_at_offset(0, msg_arg) }?;

                    Ok(litebox_common_optee::OpteeSmcResult::Generic {
                        status: OpteeSmcReturnCode::Ok,
                    }
                    .into())
                }
                OpteeMessageCommand::CloseSession => {
                    // Decode request but don't use it - we keep the TA loaded
                    let Ok(_ta_req_info) = decode_ta_request(&msg_arg) else {
                        return Err(OpteeSmcReturnCode::EBadCmd);
                    };

                    // For persistent TA mode, CloseSession is a no-op.
                    // The TA remains loaded and will be reused for the next session.
                    // TODO: properly clean up when we support multiple TAs.

                    Ok(litebox_common_optee::OpteeSmcResult::Generic {
                        status: OpteeSmcReturnCode::Ok,
                    }
                    .into())
                }
                _ => {
                    handle_optee_msg_arg(&msg_arg)?;
                    Ok(litebox_common_optee::OpteeSmcResult::Generic {
                        status: OpteeSmcReturnCode::Ok,
                    }
                    .into())
                }
            }
        }
        _ => Ok(smc_result.into()),
    }
}

// use include_bytes! to include ldelf and (KMPP) TA binaries
const LDELF_BINARY: &[u8] = &[0u8; 0];
const TA_BINARY: &[u8] = &[0u8; 0];

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("{}", info);
    match raise_vtl0_gp_fault() {
        Ok(result) => vtl_switch(Some(result.reinterpret_as_signed())),
        Err(err) => vtl_switch(Some((err as u32).reinterpret_as_signed().neg().into())),
    };
    unreachable!()
}
