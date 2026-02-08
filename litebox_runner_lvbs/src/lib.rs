// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::{ops::Neg, panic::PanicInfo};
use litebox::{
    mm::linux::PAGE_SIZE,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeSmcArgs, OpteeSmcResult, OpteeSmcReturnCode, TeeOrigin,
    TeeResult, UteeEntryFunc, UteeParams,
};
use litebox_platform_lvbs::{
    arch::{gdt, get_core_id, instrs::hlt_loop, interrupts},
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
    decode_ta_request, handle_optee_msg_args, handle_optee_smc_args, update_optee_msg_args,
};
use litebox_shim_optee::session::{
    MAX_TA_INSTANCES, SessionManager, TaInstance, allocate_session_id,
};
use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr};
use once_cell::race::OnceBox;
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

            // Add a small range of mapped memory to the global allocator for populating the base page table.
            // `VTL1_INIT_HEAP_START_PAGE` and `VTL1_INIT_HEP_SIZE` specify a physical address range which is
            // not used by the VTL1 kernel.
            let mem_fill_start =
                TruncateExt::<usize>::truncate(Platform::pa_to_va(vtl1_start).as_u64())
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
            let mem_fill_start: usize = get_heap_start_address().truncate();
            let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE
                - TruncateExt::<usize>::truncate(get_heap_start_address() - start);
            unsafe {
                Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
            }
            debug_serial_println!(
                "adding a range of memory to the global allocator: start = {:#x}, size = {:#x}",
                mem_fill_start,
                mem_fill_size
            );

            let pml4_table_addr = vtl1_start + (PAGE_SIZE * VTL1_PML4E_PAGE) as u64;
            let platform = Platform::new(pml4_table_addr, vtl1_start, vtl1_end);
            ret = Some(platform);
            litebox_platform_multiplex::set_platform(platform);

            // Add the rest of the VTL1 memory to the global allocator once they are mapped to the base page table.
            let mem_fill_start = mem_fill_start + mem_fill_size;
            let mem_fill_size = TruncateExt::<usize>::truncate(
                size - (mem_fill_start as u64 - Platform::pa_to_va(vtl1_start).as_u64()),
            );
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
    let smc_args_updated = optee_smc_handler(smc_args_addr);

    // Write back the SMC arguments page to normal world memory.
    // All OP-TEE return codes (success or error) are delivered via smc_args.args[0].
    let mut smc_args_ptr = NormalWorldMutPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
        .map_err(|_| litebox_common_linux::errno::Errno::EINVAL)?;
    // SAFETY: The SMC args are written back to normal world memory.
    unsafe { smc_args_ptr.write_at_offset(0, smc_args_updated) }
        .map_err(|_| litebox_common_linux::errno::Errno::EFAULT)?;
    Ok(0)
}

/// Get the global session manager.
fn session_manager() -> &'static SessionManager {
    static SESSION_MANAGER: OnceBox<SessionManager> = OnceBox::new();
    SESSION_MANAGER.get_or_init(|| Box::new(SessionManager::new()))
}

/// Switch to the base page table.
///
/// This must be called before returning to VTL0 to ensure VTL1 reentry is
/// always done with the base page table.
///
/// # Safety
///
/// The caller must ensure that no references to user-space memory are held
/// after the switch.
#[inline]
unsafe fn switch_to_base_page_table() {
    let platform = litebox_platform_multiplex::platform();
    // Safety: We're switching to base page table which contains valid mappings
    // for all kernel memory that will be accessed after the switch.
    unsafe {
        platform.page_table_manager().load_base();
    }
}

/// Creates a new task-specific page table.
#[inline]
fn create_task_page_table() -> Result<usize, OpteeSmcReturnCode> {
    let platform = litebox_platform_multiplex::platform();
    platform
        .create_task_page_table()
        .map_err(|_| OpteeSmcReturnCode::ENomem)
}

/// Switches to a task-specific page table.
///
/// # Safety
///
/// The caller must ensure that no references to user-space memory from a different
/// task's address space are held after the switch.
#[inline]
unsafe fn switch_to_task_page_table(task_pt_id: usize) -> Result<(), OpteeSmcReturnCode> {
    let platform = litebox_platform_multiplex::platform();
    // Safety: We're switching to a task page table which contains valid mappings
    // for both kernel memory and the specific task's user-space memory.
    unsafe {
        platform
            .page_table_manager()
            .load_task(task_pt_id)
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)
    }
}

/// Deletes a task-specific page table.
///
/// # Safety
///
/// The caller must ensure that no references or pointers to memory mapped
/// by this page table are held after deletion.
#[inline]
unsafe fn delete_task_page_table(task_pt_id: usize) -> Result<(), OpteeSmcReturnCode> {
    let platform = litebox_platform_multiplex::platform();
    // Safety: caller guarantees no dangling references
    unsafe {
        platform
            .delete_task_page_table(task_pt_id)
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)
    }
}

/// Handler for OP-TEE SMC calls.
///
/// This function processes SMC calls from the normal world (VTL0) and dispatches them
/// to the appropriate handlers based on the command type.
///
/// For TA requests (OpenSession, InvokeCommand, CloseSession), it uses `decode_ta_request`
/// to extract the TA request information and load/run it using `OpteeShim`.
///
/// OpenSession for multi-instance TA creates:
/// - A new task page table for memory isolation
/// - A new TA instance with its own state
/// - An entry in the global session map
///
/// OpenSession for single-instance TA reuses existing TA instance if available,
/// otherwise creates a new one.
///
/// InvokeCommand looks up the session and switches to its page table.
/// CloseSession removes the session and cleans up its page table if no more sessions use it.
///
/// Before returning to VTL0, we always switch back to the base page table.
///
/// # Panics
///
/// Panics if `loaded_program.entrypoints` is `None` when attempting to run the TA.
/// This should not happen in normal operation as `entrypoints` is always `Some` after
/// loading.
///
/// # Return Value
///
/// This function always returns `OpteeSmcArgs` with the result code in `args[0]`.
/// The OP-TEE driver expects all return codes (success or error) to be delivered via
/// `smc_args.args[0]`.
fn optee_smc_handler(smc_args_addr: usize) -> OpteeSmcArgs {
    use OpteeMessageCommand::{CloseSession, InvokeCommand, OpenSession};

    // Helper to create error response when we don't read smc_args from the normal world yet
    let make_error_response = |code: OpteeSmcReturnCode| -> OpteeSmcArgs {
        let mut args = OpteeSmcArgs::default();
        args.set_return_code(code);
        args
    };

    let Ok(mut smc_args_ptr) =
        NormalWorldConstPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
    else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    // SAFETY: The SMC args are read from normal world memory into an owned copy.
    let Ok(mut smc_args) = (unsafe { smc_args_ptr.read_at_offset(0) }) else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    let Ok(msg_args_phys_addr) = smc_args.optee_msg_args_phys_addr() else {
        smc_args.set_return_code(OpteeSmcReturnCode::EBadAddr);
        return *smc_args;
    };
    let Ok(smc_result) = handle_optee_smc_args(&mut smc_args) else {
        smc_args.set_return_code(OpteeSmcReturnCode::EBadCmd);
        return *smc_args;
    };
    match smc_result {
        OpteeSmcResult::CallWithArg { msg_args } => {
            let mut msg_args = *msg_args;
            debug_serial_println!("OP-TEE SMC with MsgArgs Command: {:?}", msg_args.cmd);
            let result = match msg_args.cmd {
                OpenSession => handle_open_session(&mut msg_args, msg_args_phys_addr),
                InvokeCommand => handle_invoke_command(&mut msg_args, msg_args_phys_addr),
                CloseSession => handle_close_session(&mut msg_args, msg_args_phys_addr),
                _ => handle_optee_msg_args(&msg_args),
            };

            // Always switch back to base page table before returning to VTL0
            // Safety: No user-space memory references are held after this point
            unsafe { switch_to_base_page_table() };

            match result {
                Ok(()) => smc_args.set_return_code(OpteeSmcReturnCode::Ok),
                Err(e) => smc_args.set_return_code(e),
            }
            *smc_args
        }
        _ => smc_result.into(),
    }
}

/// Handle OpenSession command.
///
/// For multi-instance TAs, creates a new task page table and loads ldelf/TA into it.
/// For single-instance TAs (TA_FLAG_SINGLE_INSTANCE), reuses existing TA instance.
///
/// On success, the session is registered and msg_args is updated with the session ID.
/// On failure (including TA returning error), msg_args is updated with the error code
/// and appropriate cleanup is performed (page table teardown for new instances,
/// instance cleanup for TARGET_DEAD on single-instance TAs with no other sessions).
fn handle_open_session(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::OpenSession {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }

    let ta_uuid = ta_req_info.uuid.ok_or(OpteeSmcReturnCode::EBadCmd)?;
    let client_identity = ta_req_info.client_identity;
    let params = &ta_req_info.params;

    if let Some(existing) = session_manager().get_single_instance(&ta_uuid) {
        // Try to reuse existing single-instance TA, or create a new instance
        // If the TA is busy (lock held), return EThreadLimit - driver will wait and retry
        open_session_single_instance(
            msg_args,
            msg_args_phys_addr,
            existing,
            params,
            ta_uuid,
            &ta_req_info,
        )
    } else {
        open_session_new_instance(
            msg_args,
            msg_args_phys_addr,
            params,
            ta_uuid,
            client_identity,
            &ta_req_info,
        )
    }
}

/// Open a new session on an existing single-instance TA.
///
/// Returns `Err(OpteeSmcReturnCode::EThreadLimit)` if the TA instance is currently in use.
/// The Linux driver will wait and retry automatically.
///
/// If the TA's OpenSession entry point returns an error, the session is not registered.
/// For cleanup semantics, see OP-TEE OS `tee_ta_open_session()` in `tee_ta_manager.c`.
#[allow(clippy::type_complexity)]
fn open_session_single_instance(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    instance_arc: Arc<SpinMutex<TaInstance>>,
    params: &[litebox_common_optee::UteeParamOwned],
    ta_uuid: litebox_common_optee::TeeUuid,
    ta_req_info: &litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>,
) -> Result<(), OpteeSmcReturnCode> {
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let instance = instance_arc
        .try_lock()
        .ok_or(OpteeSmcReturnCode::EThreadLimit)?;

    // Allocate session ID BEFORE calling load_ta_context so TA gets correct ID
    let runner_session_id = allocate_session_id().ok_or(OpteeSmcReturnCode::EBusy)?;

    debug_serial_println!(
        "Reusing single-instance TA: uuid={:?}, task_pt_id={}, session_id={}",
        ta_uuid,
        instance.task_page_table_id,
        runner_session_id
    );

    let task_pt_id = instance.task_page_table_id;
    let ta_flags = instance.loaded_program.ta_flags;

    // Switch to the existing TA's page table
    unsafe { switch_to_task_page_table(task_pt_id)? };

    // Load TA context with parameters for OpenSession - pass actual session_id
    instance
        .loaded_program
        .entrypoints
        .as_ref()
        .ok_or(OpteeSmcReturnCode::EBadCmd)?
        .load_ta_context(
            params,
            Some(runner_session_id),
            UteeEntryFunc::OpenSession as u32,
            None,
        )
        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

    // Run the TA's OpenSession entry point using reference-based reenter
    let mut ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::reenter_thread_ref(
            instance.loaded_program.entrypoints.as_ref().unwrap(),
            &mut ctx,
        );
    }

    // Read TA output parameters from the stack buffer
    let params_address = instance
        .loaded_program
        .params_address
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let ta_params = unsafe { *(params_address as *const UteeParams) };

    // Check the return code from the TA's OpenSession entry point
    let return_code: u32 = ctx.rax.truncate();
    let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

    // Drop the lock before potential cleanup
    drop(instance);

    // Per OP-TEE OS: if OpenSession fails, don't register the session
    // Reference: tee_ta_open_session() in tee_ta_manager.c
    if return_code != TeeResult::Success {
        debug_serial_println!(
            "OpenSession failed on single-instance TA: return_code={:?}",
            return_code
        );

        // For single-instance TAs, only clean up on TARGET_DEAD (panic).
        // Regular errors (access denied, bad params, etc.) don't mean the TA is dead -
        // it can still serve future OpenSession requests from other clients.
        if return_code == TeeResult::TargetDead {
            // Check if any other sessions are using this instance by counting sessions
            // in the session map that reference this TA instance.
            let session_count = session_manager()
                .sessions()
                .count_sessions_for_instance(&instance_arc);

            if session_count == 0 {
                debug_serial_println!(
                    "Single-instance TA panicked with no other sessions, cleaning up"
                );

                // Write error response BEFORE switching page tables (accesses user memory)
                write_msg_args_to_normal_world(
                    msg_args,
                    msg_args_phys_addr,
                    return_code,
                    None, // No session ID on failure
                    Some(&ta_params),
                    Some(ta_req_info),
                )?;

                session_manager().remove_single_instance(&ta_uuid);

                // Switch to base page table and delete the task page table
                unsafe { switch_to_base_page_table() };
                // Safety: We've switched to the base page table above.
                let _ = unsafe { delete_task_page_table(task_pt_id) };

                // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
                // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
                // cleaning it up. Currently we always clean up on panic.

                return Ok(());
            }
        }

        // Write error response back to normal world
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None, // No session ID on failure
            Some(&ta_params),
            Some(ta_req_info),
        )?;

        return Ok(());
    }

    // Success: register session
    session_manager().register_session(runner_session_id, instance_arc.clone(), ta_uuid, ta_flags);

    write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        return_code,
        Some(runner_session_id),
        Some(&ta_params),
        Some(ta_req_info),
    )?;

    debug_serial_println!(
        "OpenSession complete on single-instance TA: session_id={}",
        runner_session_id
    );

    Ok(())
}

/// Create a new TA instance for a session.
///
/// If ldelf loading or OpenSession entry point fails, the page table is torn down.
/// Per OP-TEE OS semantics: if OpenSession returns non-success, cleanup happens.
fn open_session_new_instance(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    params: &[litebox_common_optee::UteeParamOwned],
    ta_uuid: litebox_common_optee::TeeUuid,
    client_identity: Option<litebox_common_optee::TeeIdentity>,
    ta_req_info: &litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>,
) -> Result<(), OpteeSmcReturnCode> {
    // Check TA instance limit
    // TODO: consider better resource management strategy
    if session_manager().instance_count() >= MAX_TA_INSTANCES {
        debug_serial_println!("TA instance limit reached ({} instances)", MAX_TA_INSTANCES);
        return Err(OpteeSmcReturnCode::ENomem);
    }

    // Create and switch to new page table
    let task_pt_id = create_task_page_table()?;

    debug_serial_println!("Created task page table ID: {}", task_pt_id);

    unsafe {
        switch_to_task_page_table(task_pt_id).inspect_err(|_| {
            // Safety: switch_to_task_page_table failed, so task page table is not active.
            let _ = delete_task_page_table(task_pt_id);
        })?;
    }

    // Allocate session ID before loading - return EBusy to normal world if exhausted
    let runner_session_id = allocate_session_id().ok_or_else(|| {
        unsafe { switch_to_base_page_table() };
        // Safety: We've switched to the base page table above.
        let _ = unsafe { delete_task_page_table(task_pt_id) };
        OpteeSmcReturnCode::EBusy
    })?;

    // Load ldelf and TA - Box immediately to keep at fixed heap address
    let shim = litebox_shim_optee::OpteeShimBuilder::new().build();
    let loaded_program = Box::new(
        shim.load_ldelf(
            LDELF_BINARY,
            ta_uuid,
            Some(TA_BINARY),
            client_identity,
            runner_session_id,
        )
        .map_err(|_| {
            unsafe { switch_to_base_page_table() };
            // Safety: We've switched to the base page table above.
            let _ = unsafe { delete_task_page_table(task_pt_id) };
            OpteeSmcReturnCode::ENomem
        })?,
    );

    let ta_flags = loaded_program.ta_flags;

    debug_serial_println!(
        "TA flags: {:?}, single_instance={}",
        ta_flags,
        ta_flags.is_single_instance()
    );

    // Run ldelf to load the TA using reference-based run to avoid moving the shim
    let mut ldelf_ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::run_thread_ref(
            loaded_program.entrypoints.as_ref().unwrap(),
            &mut ldelf_ctx,
        );
    }

    // Check ldelf return code (TA_CreateEntryPoint result)
    let ldelf_return_code: u32 = ldelf_ctx.rax.truncate();
    let ldelf_return_code =
        TeeResult::try_from(ldelf_return_code).unwrap_or(TeeResult::GenericError);
    if ldelf_return_code != TeeResult::Success {
        debug_serial_println!(
            "ldelf/TA_CreateEntryPoint failed: return_code={:?}",
            ldelf_return_code
        );
        unsafe { switch_to_base_page_table() };
        // Safety: We've switched to the base page table above.
        let _ = unsafe { delete_task_page_table(task_pt_id) };

        // Write error response back to normal world
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            ldelf_return_code,
            None, // No session ID on failure
            None,
            Some(ta_req_info),
        )?;

        return Ok(());
    }

    // Load TA context with parameters for OpenSession - pass actual session_id
    loaded_program.entrypoints.as_ref().ok_or_else(|| {
        unsafe { switch_to_base_page_table() };
        // Safety: We've switched to the base page table above.
        let _ = unsafe { delete_task_page_table(task_pt_id) };
        OpteeSmcReturnCode::EBadCmd
    })?;
    loaded_program
        .entrypoints
        .as_ref()
        .unwrap()
        .load_ta_context(
            params,
            Some(runner_session_id),
            UteeEntryFunc::OpenSession as u32,
            None,
        )
        .map_err(|_| {
            unsafe { switch_to_base_page_table() };
            // Safety: We've switched to the base page table above.
            let _ = unsafe { delete_task_page_table(task_pt_id) };
            OpteeSmcReturnCode::EBadCmd
        })?;

    // Run the TA entry function using reference-based reenter to avoid moving the shim
    let mut ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::reenter_thread_ref(
            loaded_program.entrypoints.as_ref().unwrap(),
            &mut ctx,
        );
    }

    // Read TA output parameters from the stack buffer
    let params_address = loaded_program
        .params_address
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let ta_params = unsafe { *(params_address as *const UteeParams) };

    // Check the return code from the TA's OpenSession entry point
    let return_code: u32 = ctx.rax.truncate();
    let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

    // Per OP-TEE OS: if OpenSession fails, tear down the instance
    // Reference: tee_ta_open_session() in tee_ta_manager.c
    if return_code != TeeResult::Success {
        debug_serial_println!(
            "OpenSession failed on new instance: return_code={:?}",
            return_code
        );

        // Write error response back to normal world
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None, // No session ID on failure
            Some(&ta_params),
            Some(ta_req_info),
        )?;

        // Tear down the page table - no session was registered
        unsafe { switch_to_base_page_table() };
        // Safety: We've switched to the base page table above.
        let _ = unsafe { delete_task_page_table(task_pt_id) };

        return Ok(());
    }

    // Success: create TA instance - loaded_program is already boxed, no move happens
    let instance = Arc::new(SpinMutex::new(TaInstance {
        shim,
        loaded_program,
        task_page_table_id: task_pt_id,
    }));

    // Cache single-instance TAs for future sessions
    if ta_flags.is_single_instance() {
        session_manager().cache_single_instance(ta_uuid, instance.clone());
    }

    // Register session (runner_session_id already allocated above)
    session_manager().register_session(runner_session_id, instance.clone(), ta_uuid, ta_flags);

    // Write success response back to normal world
    write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        return_code,
        Some(runner_session_id),
        Some(&ta_params),
        Some(ta_req_info),
    )?;

    debug_serial_println!(
        "OpenSession complete: session_id={}, single_instance={}",
        runner_session_id,
        ta_flags.is_single_instance()
    );

    Ok(())
}

/// Handle InvokeCommand.
///
/// Looks up the session by ID, switches to its page table, and runs the command.
///
/// Per OP-TEE OS semantics: if the TA panics (returns TARGET_DEAD), the session
/// should be cleaned up. For single-instance TAs with no other sessions, the
/// entire instance is destroyed.
fn handle_invoke_command(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::InvokeCommand {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }
    let cmd_id = ta_req_info.cmd_id;
    let params = &ta_req_info.params;
    let session_id = ta_req_info.session;

    // Get the session entry from the session map (need full entry for potential cleanup)
    let session_entry = session_manager()
        .get_session_entry(session_id)
        .ok_or(OpteeSmcReturnCode::EBadCmd)?;
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let Some(instance) = session_entry.instance.try_lock() else {
        return Err(OpteeSmcReturnCode::EThreadLimit);
    };

    let task_pt_id = instance.task_page_table_id;

    // Switch to the TA instance's page table
    unsafe { switch_to_task_page_table(task_pt_id)? };

    debug_serial_println!(
        "InvokeCommand: session_id={}, task_pt_id={}, cmd_id={}",
        session_id,
        task_pt_id,
        cmd_id
    );

    // Load TA context with parameters and cmd_id - pass actual session_id
    let entrypoints_ref = instance.loaded_program.entrypoints.as_ref().unwrap();
    entrypoints_ref
        .load_ta_context(
            params.as_slice(),
            Some(session_id),
            UteeEntryFunc::InvokeCommand as u32,
            Some(cmd_id),
        )
        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

    // Run the TA entry function using reference-based reenter to avoid moving the shim
    let mut ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::reenter_thread_ref(
            instance.loaded_program.entrypoints.as_ref().unwrap(),
            &mut ctx,
        );
    }

    // params_address is constant - stack buffer is reused across invocations
    let params_address = instance
        .loaded_program
        .params_address
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let ta_params = unsafe { *(params_address as *const UteeParams) };

    let return_code: u32 = ctx.rax.truncate();
    let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

    // Per OP-TEE OS: if TA panics (TARGET_DEAD), clean up the session/instance
    // Reference: tee_ta_invoke_command() in tee_ta_manager.c
    if return_code == TeeResult::TargetDead {
        debug_serial_println!(
            "InvokeCommand: TA panicked (TARGET_DEAD), session_id={}",
            session_id
        );

        let ta_uuid = session_entry.ta_uuid;
        let ta_flags = session_entry.ta_flags;
        let instance_arc = session_entry.instance.clone();

        // Drop the instance lock before cleanup
        drop(instance);

        // Remove the session from the map
        session_manager().unregister_session(session_id);

        // Check if this was the last session using the TA instance by counting
        // remaining sessions that reference this instance.
        let remaining_sessions = session_manager()
            .sessions()
            .count_sessions_for_instance(&instance_arc);
        let is_last_session = remaining_sessions == 0;

        // Write response BEFORE switching page tables (accesses user memory)
        write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None,
            Some(&ta_params),
            Some(&ta_req_info),
        )?;

        if is_last_session {
            // Clear single-instance cache if applicable
            if ta_flags.is_single_instance() {
                session_manager().remove_single_instance(&ta_uuid);
            }

            // Switch to base page table and delete the task page table
            unsafe { switch_to_base_page_table() };
            // Safety: We've switched to the base page table above.
            let _ = unsafe { delete_task_page_table(task_pt_id) };
            debug_serial_println!(
                "InvokeCommand: cleaned up dead TA instance, task_pt_id={}",
                task_pt_id
            );

            // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
            // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
            // cleaning it up. Currently we always clean up on panic.
        }

        return Ok(());
    }

    write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        return_code,
        None,
        Some(&ta_params),
        Some(&ta_req_info),
    )?;

    Ok(())
}

/// Handle CloseSession command.
///
/// Looks up the session, enters the TA to call TA_CloseSessionEntryPoint,
/// then removes the session from the map. For single-instance TAs, the TA
/// is only destroyed when the last session closes.
fn handle_close_session(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let ta_req_info = decode_ta_request(msg_args).map_err(|_| OpteeSmcReturnCode::EBadCmd)?;
    if ta_req_info.entry_func != UteeEntryFunc::CloseSession {
        return Err(OpteeSmcReturnCode::EBadCmd);
    }
    let session_id = ta_req_info.session;

    debug_serial_println!("CloseSession: session_id={}", session_id);

    // Get the session entry from the session map
    let session_entry = session_manager()
        .get_session_entry(session_id)
        .ok_or(OpteeSmcReturnCode::EBadCmd)?;
    // Use try_lock to avoid spinning - return EThreadLimit if TA is in use
    // The Linux driver will handle this by waiting and retrying
    let Some(instance) = session_entry.instance.try_lock() else {
        return Err(OpteeSmcReturnCode::EThreadLimit);
    };

    let task_pt_id = instance.task_page_table_id;

    // Switch to the TA instance's page table
    unsafe { switch_to_task_page_table(task_pt_id)? };

    // Load TA context for CloseSession (no params, no cmd_id) - pass actual session_id
    instance
        .loaded_program
        .entrypoints
        .as_ref()
        .unwrap()
        .load_ta_context(
            &[],
            Some(session_id),
            UteeEntryFunc::CloseSession as u32,
            None,
        )
        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

    // Run the TA entry function (TA_CloseSessionEntryPoint)
    let mut ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::reenter_thread_ref(
            instance.loaded_program.entrypoints.as_ref().unwrap(),
            &mut ctx,
        );
    }

    // CloseSession always succeeds (TA_CloseSessionEntryPoint returns void)
    write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        TeeResult::Success,
        None,
        None,
        None,
    )?;

    // Clone the instance Arc before dropping the lock for later cleanup check
    let instance_arc = session_entry.instance.clone();

    // Drop the instance lock before removing from map
    drop(instance);

    // Remove the session entry from the map
    let removed_entry = session_manager().unregister_session(session_id);

    // Check if this was the last session using the TA instance by counting
    // remaining sessions that reference this instance.
    let remaining_sessions = session_manager()
        .sessions()
        .count_sessions_for_instance(&instance_arc);

    // If this was the last session using the TA instance, clean up (unless keep_alive is set)
    if remaining_sessions == 0 {
        if let Some(entry) = removed_entry {
            // If this is a single-instance TA with keep_alive flag, don't remove it from memory.
            // Note: keep_alive is only meaningful for single-instance TAs.
            if entry.ta_flags.is_single_instance() && entry.ta_flags.is_keep_alive() {
                debug_serial_println!(
                    "CloseSession complete: session_id={}, TA kept alive (INSTANCE_KEEP_ALIVE flag)",
                    session_id
                );
                return Ok(());
            }

            // Clear single-instance cache if this was a single-instance TA
            if entry.ta_flags.is_single_instance() {
                session_manager().remove_single_instance(&entry.ta_uuid);
            }

            let instance = entry.instance.lock();
            let task_pt_id = instance.task_page_table_id;

            // Make sure we're on the base page table before deleting
            unsafe { switch_to_base_page_table() };

            // Drop the instance to release shim/loaded_program resources
            drop(instance);
            drop(entry);

            // Delete the task page table
            // Safety: We've switched to the base page table above.
            let _ = unsafe { delete_task_page_table(task_pt_id) };

            debug_serial_println!(
                "CloseSession complete: deleted task_pt_id={} (last session)",
                task_pt_id
            );
        }
    } else {
        debug_serial_println!(
            "CloseSession complete: session_id={}, other sessions remaining on TA",
            session_id
        );
    }

    Ok(())
}

/// Update msg_args with return values and write back to normal world memory.
///
/// Per OP-TEE OS semantics:
/// - `TeeOrigin::Tee` is used when the error comes from TEE itself (panic/TARGET_DEAD)
/// - `TeeOrigin::TrustedApp` is used when the error comes from the TA
///
/// # Security Note
///
/// This function accesses TA userspace memory via `update_optee_msg_args` to copy out
/// output parameters. It must be called **before** switching page tables or deleting
/// the task page table, otherwise the userspace memory references become invalid.
///
/// # Panics
///
/// Panics if called while the base page table is active (i.e., not in a TA context).
#[inline]
fn write_msg_args_to_normal_world(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    return_code: TeeResult,
    session_id: Option<u32>,
    ta_params: Option<&UteeParams>,
    ta_req_info: Option<&litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>>,
) -> Result<(), OpteeSmcReturnCode> {
    // Ensure we're on a task page table, not the base page table.
    // Accessing TA userspace memory requires the TA's page table to be active.
    debug_assert!(
        !litebox_platform_multiplex::platform()
            .page_table_manager()
            .is_base_page_table_active(),
        "write_msg_args_to_normal_world called on base page table"
    );

    // Per OP-TEE: origin is TEE only if panicked (TARGET_DEAD), otherwise TrustedApp
    let origin = if return_code == TeeResult::TargetDead {
        TeeOrigin::Tee
    } else {
        TeeOrigin::TrustedApp
    };
    update_optee_msg_args(
        return_code,
        origin,
        session_id,
        ta_params,
        ta_req_info,
        msg_args,
    )?;
    let mut ptr =
        NormalWorldMutPtr::<OpteeMsgArgs, PAGE_SIZE>::with_usize(msg_args_phys_addr.truncate())?;
    // SAFETY: Writing msg_args back to normal world memory at a valid address.
    unsafe { ptr.write_at_offset(0, *msg_args) }?;
    Ok(())
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
    // We assume that once this VTL1 kernel panics, we don't try to resume its execution.
    // This is because, after the panic, the kernel is in an undefined state.
    // Switch back to VTL0, do crash dump, and reboot the machine.
    hlt_loop()
}
