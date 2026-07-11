// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![no_std]

extern crate alloc;

use alloc::{boxed::Box, vec};
use core::{ops::Neg, panic::PanicInfo};
use litebox::{
    mm::linux::PAGE_SIZE,
    platform::RawConstPointer,
    utils::{ReinterpretSignedExt, TruncateExt},
};
use litebox_common_linux::errno::Errno;
use litebox_common_optee::{
    OpteeMessageCommand, OpteeMsgArgs, OpteeRpcArgs, OpteeSmcArgs, OpteeSmcResult,
    OpteeSmcReturnCode, TeeOrigin, TeeResult, UteeEntryFunc, UteeParams, optee_msg_args_total_size,
};
use litebox_platform_lvbs::{
    arch::{gdt, instrs::hlt_loop, interrupts, timer},
    debug_serial_println,
    host::{bootparam::get_vtl1_memory_info, per_cpu_variables},
    mm::MemoryProvider,
    mshv::{
        NUM_VTLCALL_PARAMS, VsmFunction, hvcall,
        vsm::vsm_dispatch,
        vsm_intercept::raise_vtl0_gp_fault,
        vtl_switch::{vtl_switch, vtl_switch_init},
        vtl1_mem_layout::{
            VSM_SK_PTE_PAGES_COUNT, VTL1_INIT_HEAP_SIZE, VTL1_INIT_HEAP_START_PAGE,
            VTL1_PML4E_PAGE, VTL1_PRE_POPULATED_MEMORY_SIZE, VTL1_PTE_0_PAGE, VTL1_REMAP_PDE_PAGE,
            VTL1_REMAP_PDPT_PAGE, get_heap_start_address, get_memory_base_address,
            get_rela_end_address, get_rela_start_address, get_text_end_address,
            get_text_start_address,
        },
    },
    serial_println,
};
use litebox_platform_multiplex::Platform;
use litebox_shim_optee::msg_handler::{
    decode_ta_request, handle_optee_msg_args, handle_optee_smc_args, update_optee_msg_args,
};
use litebox_shim_optee::session::{OpenSessionTarget, TaInstance, session_manager};
use litebox_shim_optee::{NormalWorldConstPtr, NormalWorldMutPtr, UserConstPtr};

/// Seed the initial heap regions so the global allocator has enough memory
/// for slab-backed allocations (the slab needs >= 2 MB backing pages).
pub fn seed_initial_heap() {
    let vtl1_base_va = get_memory_base_address();
    let vtl1_start = Platform::va_to_pa(x86_64::VirtAddr::new(vtl1_base_va));

    let mem_fill_start =
        TruncateExt::<usize>::trunc(vtl1_base_va) + VTL1_INIT_HEAP_START_PAGE * PAGE_SIZE;
    unsafe {
        Platform::mem_fill_pages(mem_fill_start, VTL1_INIT_HEAP_SIZE);
    }
    debug_serial_println!(
        "heap: seed init region (pages {}..+{:#x}): VA {:#x}, size {:#x}",
        VTL1_INIT_HEAP_START_PAGE,
        VTL1_INIT_HEAP_SIZE,
        mem_fill_start,
        VTL1_INIT_HEAP_SIZE
    );

    // Add pre-populated region (_heap_start .. end of Phase 1 mapping).
    let heap_va = get_heap_start_address();
    let mem_fill_start: usize = heap_va.trunc();
    let heap_phys = Platform::va_to_pa(x86_64::VirtAddr::new(heap_va)).as_u64();
    let heap_offset: usize = TruncateExt::<usize>::trunc(heap_phys - vtl1_start.as_u64());
    let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE - heap_offset;
    unsafe {
        Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
    }
    debug_serial_println!(
        "heap: add pre-populated region (_heap_start..Phase 1 end): VA {:#x}, size {:#x}",
        mem_fill_start,
        mem_fill_size
    );
}

/// Initialize the current core.
///
/// When `is_bsp` is `true`, creates the platform, sets up page tables, and
/// reclaims early memory.
/// All cores then initialize hypercalls, GDT, IDT, interrupts, and syscall
/// support.
///
/// # Panics
///
/// Panics if VTL1 memory info is unavailable (BSP) or if hypercall
/// initialization fails.
pub fn init(is_bsp: bool) -> Option<&'static Platform> {
    let ret = if is_bsp {
        let (start, size) = get_vtl1_memory_info().expect("Failed to get memory info");
        let min_vtl1_size = ((VTL1_REMAP_PDE_PAGE + 1) * PAGE_SIZE) as u64;
        assert!(
            size >= min_vtl1_size,
            "VTL1 memory size is too small for fixed boot layout"
        );
        let vtl1_start = x86_64::PhysAddr::new(start);
        // this `checked_add` covers all `vtl1_start + offset` calculations within this function.
        let vtl1_end = x86_64::PhysAddr::new(
            start
                .checked_add(size)
                .expect("VTL1 memory range overflow in init()"),
        );

        // Re-compute the pre-populated region bounds needed for the
        // remaining-memory add after `Platform::new()` below.
        let heap_va = get_heap_start_address();
        let mem_fill_start: usize = heap_va.trunc();
        let heap_phys = Platform::va_to_pa(x86_64::VirtAddr::new(heap_va)).as_u64();
        let heap_offset: usize = TruncateExt::<usize>::trunc(heap_phys - start);
        let mem_fill_size = VTL1_PRE_POPULATED_MEMORY_SIZE - heap_offset;

        // Text section boundaries. These are used by the platform to mark
        // code pages executable and everything else NO_EXECUTE (DEP).
        // After two-phase relocation, linker symbols return
        // high-canonical VAs; convert to PA for the page table mapper.
        let text_phys_start = Platform::va_to_pa(x86_64::VirtAddr::new(get_text_start_address()));
        let text_phys_end = Platform::va_to_pa(x86_64::VirtAddr::new(get_text_end_address()));

        // Reclaim .rela.dyn section memory now that relocations have been applied
        // and we are running at high-canonical addresses.
        // After two-phase relocation, `get_rela_start/end_address()` return
        // high-canonical VAs. Use directly for the allocator.
        let rela_va = get_rela_start_address();
        let rela_size: usize = (get_rela_end_address() - rela_va).trunc();
        if rela_size > 0 {
            let rela_virt: usize = rela_va.trunc();
            unsafe {
                Platform::mem_fill_pages(rela_virt, rela_size);
            }
            debug_serial_println!(
                "heap: reclaim .rela.dyn section: VA {:#x}, size {:#x}",
                rela_virt,
                rela_size
            );
        }

        let platform = Platform::new(vtl1_start, vtl1_end, text_phys_start, text_phys_end);
        litebox_platform_multiplex::set_platform(platform);

        // Reclaim Phase 1 / VTL0 page table frames now that Platform::new()
        // has loaded a fresh base page table covering all VTL1 memory.
        // These physical pages are no longer referenced by CR3.
        {
            // Reclaim pages 2–12 (PML4, PDPT, PDE, 8 PTE pages)
            let early_pt_pa = vtl1_start + (VTL1_PML4E_PAGE * PAGE_SIZE) as u64;
            let early_pt_start: usize =
                TruncateExt::<usize>::trunc(Platform::pa_to_va(early_pt_pa).as_u64());
            let early_pt_size: usize =
                (VTL1_PTE_0_PAGE + VSM_SK_PTE_PAGES_COUNT - VTL1_PML4E_PAGE) * PAGE_SIZE;
            // Safety: the early page table frames are no longer referenced
            // (CR3 now points to the Phase 2 base page table).
            unsafe {
                Platform::mem_fill_pages(early_pt_start, early_pt_size);
            }
            debug_serial_println!(
                "heap: reclaim early page table frames (pages {}..{}): VA {:#x}, size {:#x}",
                VTL1_PML4E_PAGE,
                VTL1_PML4E_PAGE + (early_pt_size / PAGE_SIZE),
                early_pt_start,
                early_pt_size
            );

            // NOTE: The boot stack page (VTL1_KERNEL_STACK_PAGE) MUST NOT be
            // reclaimed here. APs reuse it as their initial RSP when they
            // enter VTL1 via `hvcall_enable_vp_vtl`.

            // Reclaim Phase 1 PDPT and PDE pages
            let remap_pt_pa = vtl1_start + (VTL1_REMAP_PDPT_PAGE * PAGE_SIZE) as u64;
            let remap_pt_start: usize =
                TruncateExt::<usize>::trunc(Platform::pa_to_va(remap_pt_pa).as_u64());
            let remap_pt_size: usize = (VTL1_REMAP_PDE_PAGE - VTL1_REMAP_PDPT_PAGE + 1) * PAGE_SIZE;
            unsafe {
                Platform::mem_fill_pages(remap_pt_start, remap_pt_size);
            }
            debug_serial_println!(
                "heap: reclaim Phase 1 remap PT frames (pages {}..{}): VA {:#x}, size {:#x}",
                VTL1_REMAP_PDPT_PAGE,
                VTL1_REMAP_PDE_PAGE + 1,
                remap_pt_start,
                remap_pt_size
            );
        }

        // Add the rest of the VTL1 memory to the global allocator once they are mapped to the base page table.
        let mem_fill_start = mem_fill_start + mem_fill_size;
        let vtl1_base_va = Platform::pa_to_va(vtl1_start).as_u64();
        let mem_fill_size = TruncateExt::<usize>::trunc(
            size.checked_sub((mem_fill_start as u64) - vtl1_base_va)
                .expect("remaining VTL1 memory size underflow in init()"),
        );
        unsafe {
            Platform::mem_fill_pages(mem_fill_start, mem_fill_size);
        }
        debug_serial_println!(
            "heap: add remaining VTL1 memory (post Phase 2): VA {:#x}, size {:#x}",
            mem_fill_start,
            mem_fill_size
        );

        Some(platform)
    } else {
        None
    };

    // Allocate XSAVE areas now that we are on the kernel stack (the CPUID
    // queries and aligned-vec allocations need a lot of stack space).
    per_cpu_variables::allocate_xsave_area();

    if let Err(e) = hvcall::init(is_bsp) {
        panic!("Err: {:?}", e);
    }
    gdt::init();
    interrupts::init_idt();
    x86_64::instructions::interrupts::enable();
    Platform::enable_syscall_support();

    // Configure this CPU's STIMER preemption timer (VTL1 self-preemption).
    // Per-CPU; safe to call on BSP and APs.
    timer::init();

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
    let func_id: u32 = params[0].trunc();
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
    let smc_args_pfn: usize = smc_args_pfn.trunc();
    let smc_args_addr = smc_args_pfn
        .checked_mul(1usize << litebox_platform_lvbs::mshv::vtl1_mem_layout::PAGE_SHIFT)
        .ok_or(litebox_common_linux::errno::Errno::EINVAL)?;
    let smc_args_updated = optee_smc_handler(smc_args_addr);

    // Write back the SMC arguments page to normal world memory.
    // All OP-TEE return codes (success or error) are delivered via smc_args.args[0].
    let smc_args_ptr = NormalWorldMutPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
        .map_err(|_| litebox_common_linux::errno::Errno::EINVAL)?;
    smc_args_ptr
        .write_at_offset(0, smc_args_updated)
        .map_err(|_| litebox_common_linux::errno::Errno::EFAULT)?;
    Ok(0)
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

/// Enforces the invariant that the core must be on the base (kernel) page
/// table before returning to VTL0: the guard switches to the TA's task
/// page table on entry and switches back on drop, covering early-return
/// and `?` paths.
///
/// `switch_to_base_page_table` is an idempotent CR3 write, so teardown
/// paths that switch to base internally before deleting the task page
/// table can run before this guard's `Drop` — the redundant write at
/// drop time is benign.
struct TaskPageTableGuard;

impl TaskPageTableGuard {
    fn enter(task_pt_id: usize) -> Result<Self, OpteeSmcReturnCode> {
        unsafe { switch_to_task_page_table(task_pt_id)? };
        Ok(Self)
    }
}

impl Drop for TaskPageTableGuard {
    fn drop(&mut self) {
        unsafe { switch_to_base_page_table() };
    }
}

/// Tears down a TA's memory mappings and page table.
///
/// This performs the following steps in order:
/// 1. Release user-space memory mappings in the TA's page table
/// 2. Switch to the base page table
/// 3. Delete the TA's page table
///
/// # Safety
///
/// The caller must ensure that no references to user-space memory mapped by
/// this task's page table are held after this call.
unsafe fn teardown_ta_page_table(shim: &litebox_shim_optee::OpteeShim, task_pt_id: usize) {
    unsafe {
        // this function unmaps/deallocates user pages in the **active** page table, so we must
        // still be on the TA's page table.
        shim.release_user_mappings();
        switch_to_base_page_table();
        // Now delete the TA's page table without memory leak.
        let _ = delete_task_page_table(task_pt_id);
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

    let Ok(smc_args_ptr) =
        NormalWorldConstPtr::<OpteeSmcArgs, PAGE_SIZE>::with_usize(smc_args_addr)
    else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    let Ok(mut smc_args) = smc_args_ptr.read_at_offset(0) else {
        return make_error_response(OpteeSmcReturnCode::EBadAddr);
    };
    let Ok(smc_result) = handle_optee_smc_args(&mut smc_args) else {
        smc_args.set_return_code(OpteeSmcReturnCode::EBadCmd);
        return *smc_args;
    };
    if let OpteeSmcResult::CallWithArg {
        msg_args,
        rpc_args: _,
        msg_args_phys_addr,
    } = smc_result
    {
        let mut msg_args = *msg_args;
        debug_serial_println!("OP-TEE SMC with MsgArgs Command: {:?}", msg_args.cmd);
        let result = match msg_args.cmd {
            OpenSession => handle_open_session(&mut msg_args, msg_args_phys_addr),
            InvokeCommand => handle_invoke_command(&mut msg_args, msg_args_phys_addr),
            CloseSession => handle_close_session(&mut msg_args, msg_args_phys_addr),
            _ => {
                let r = handle_optee_msg_args(&msg_args);
                if r.is_ok() {
                    msg_args.ret = TeeResult::Success;
                } else {
                    msg_args.ret = TeeResult::BadParameters;
                }
                msg_args.ret_origin = TeeOrigin::Tee;
                let _ = write_non_ta_msg_args_to_normal_world(&msg_args, msg_args_phys_addr);
                r
            }
        };

        // Always switch back to base page table before returning to VTL0
        // Safety: No user-space memory references are held after this point
        unsafe { switch_to_base_page_table() };

        if let Err(e) = result {
            smc_args.set_return_code(e);
        } else {
            smc_args.set_return_code(OpteeSmcReturnCode::Ok);
        }
        *smc_args
    } else {
        smc_result.into()
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
/// instance cleanup for TARGET_DEAD on single-instance TAs).
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

    session_manager().with_ta(&ta_uuid, |target| match target {
        OpenSessionTarget::Sibling(instance) => open_session_single_instance(
            msg_args,
            msg_args_phys_addr,
            instance,
            params,
            client_identity,
            &ta_req_info,
        ),
        OpenSessionTarget::NewInstance => open_session_new_instance(
            msg_args,
            msg_args_phys_addr,
            params,
            ta_uuid,
            client_identity,
            &ta_req_info,
        ),
        OpenSessionTarget::Busy => {
            // Single-instance TA without MULTI_SESSION already has a live
            // session. Per OP-TEE OS `tee_ta_init_session_with_context`,
            // return TEE_ERROR_BUSY with origin TEE via msg_args.
            msg_args.ret = TeeResult::Busy;
            msg_args.ret_origin = TeeOrigin::Tee;
            write_non_ta_msg_args_to_normal_world(msg_args, msg_args_phys_addr)?;
            Ok(())
        }
    })
}

/// Open a new session on an existing single-instance TA.
///
/// If the TA's OpenSession entry point returns an error, the session is not registered.
/// On TARGET_DEAD, sessions for the failed instance are marked `Dead`, the matching
/// single-instance cache entry is evicted, and the TA instance is torn down.
/// For cleanup semantics, see OP-TEE OS `tee_ta_open_session()` in `tee_ta_manager.c`.
fn open_session_single_instance(
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    instance: &TaInstance,
    params: &[litebox_common_optee::UteeParamOwned],
    client_identity: Option<litebox_common_optee::TeeIdentity>,
    ta_req_info: &litebox_shim_optee::msg_handler::TaRequestInfo<PAGE_SIZE>,
) -> Result<(), OpteeSmcReturnCode> {
    let task_pt_id = instance.task_page_table_id();
    let ta_uuid = instance.uuid();
    let ta_flags = instance.loaded_program().ta_flags;

    let mut session_token = session_manager().try_acquire_open_session_token()?;
    // Safe to unwrap: session ID has been just created.
    let runner_session_id = session_token.session_id().unwrap();

    // Record the client identity before running OpenSession
    session_manager().set_session_client_identity(runner_session_id, client_identity);

    debug_serial_println!(
        "Reusing single-instance TA: uuid={:?}, task_pt_id={}, session_id={}",
        ta_uuid,
        task_pt_id,
        runner_session_id
    );

    // Switch to the existing TA's page table
    let _task_pt_guard = TaskPageTableGuard::enter(task_pt_id)?;

    // Load TA context with parameters for OpenSession - pass actual session_id
    instance
        .loaded_program()
        .entrypoints
        .as_ref()
        .ok_or(OpteeSmcReturnCode::EBadCmd)?
        .load_ta_context(
            params,
            runner_session_id,
            UteeEntryFunc::OpenSession as u32,
            None,
        )
        .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

    // Run the TA's OpenSession entry point using reference-based reenter
    let mut ctx = litebox_common_linux::PtRegs::default();
    unsafe {
        litebox_platform_lvbs::reenter_thread_ref(
            instance.loaded_program().entrypoints.as_ref().unwrap(),
            &mut ctx,
        );
    }

    // Read TA output parameters from the stack buffer
    let params_address = instance
        .loaded_program()
        .params_address
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;
    let ta_params = UserConstPtr::<UteeParams>::from_usize(params_address)
        .read_at_offset(0)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?;

    // Check the return code from the TA's OpenSession entry point
    let return_code: u32 = ctx.rax.trunc();
    let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

    // Per OP-TEE OS: if OpenSession fails, don't register the session
    // Reference: tee_ta_open_session() in tee_ta_manager.c
    if return_code != TeeResult::Success {
        debug_serial_println!(
            "OpenSession failed on single-instance TA: return_code={:?}",
            return_code
        );

        // Write error response BEFORE switching page tables (accesses user memory).
        // `with_ta`'s serialization keeps the instance alive so another core cannot
        // tear down the active page table while this core is copying TA outputs.
        let write_result = write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None, // No session ID on failure
            Some(&ta_params),
            Some(ta_req_info),
        );

        // For single-instance TAs, only clean up on TARGET_DEAD (panic).
        // Regular errors (access denied, bad params, etc.) don't mean the TA is dead -
        // it can still serve future OpenSession requests from other clients.
        if return_code == TeeResult::TargetDead {
            debug_serial_println!("Single-instance TA panicked during OpenSession, cleaning up");

            session_manager().mark_sessions_dead_for_instance(instance);
            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe {
                teardown_ta_page_table(instance.shim(), task_pt_id);
            };

            // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
            // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
            // cleaning it up. Currently we always clean up on panic.
        }

        write_result?;
        return Ok(());
    }

    // Treat write-back failure as OpenSession failure: do not publish the session.
    let write_result = write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        return_code,
        Some(runner_session_id),
        Some(&ta_params),
        Some(ta_req_info),
    );

    // Write-back failure: OpenSession succeeded inside the TA, but we cannot
    // deliver the session id to the normal world, so it will never issue a
    // matching CloseSession. For a non-keep-alive instance with no siblings
    // we tear the whole instance down, reclaiming the TA-side state, and the
    // session id is recycled by the token's drop. For keep-alive or shared
    // instances the TA still holds session-local state tagged with this id,
    // so we forget the id (disarm the token) to prevent a future OpenSession
    // from reusing it and colliding with the orphaned TA-side bookkeeping.
    if let Err(e) = write_result {
        if !ta_flags.is_keep_alive() && session_manager().count_sessions_for_instance(instance) == 0
        {
            let _ = session_manager().evict_cached_instance(instance);
            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe {
                teardown_ta_page_table(instance.shim(), task_pt_id);
            };
        } else {
            // The session id is forgotten (never recycled), so the token's drop
            // won't clear the recorded identity. Remove the client identity here.
            session_manager().clear_session_client_identity(runner_session_id);
            session_token.disarm();
        }
        return Err(e);
    }

    // Success: register a sibling session pointing at the existing instance.
    session_manager().register_sibling_session(runner_session_id, instance)?;
    session_token.disarm();

    debug_serial_println!(
        "OpenSession complete on single-instance TA: session_id={}",
        runner_session_id
    );

    Ok(())
}

/// Create a new TA instance for a session. Must be called from within a
/// [`litebox_shim_optee::session::SessionManager::with_ta`] closure.
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
    let Some(ta_bin) = find_ta_binary(ta_uuid) else {
        msg_args.session = 0;
        msg_args.ret = TeeResult::ItemNotFound;
        msg_args.ret_origin = TeeOrigin::Tee;
        write_non_ta_msg_args_to_normal_world(msg_args, msg_args_phys_addr)?;
        return Ok(());
    };

    // Token is declared before `task_pt_guard` so it drops AFTER it.
    // Marker only releases once CR3 is back to base. See
    // `try_acquire_open_session_token` for why.
    let mut session_token = session_manager().try_acquire_open_session_token()?;
    let runner_session_id = session_token.session_id().unwrap();

    let task_pt_id = create_task_page_table()?;
    debug_serial_println!("Created task page table ID: {}", task_pt_id);

    let _task_pt_guard = TaskPageTableGuard::enter(task_pt_id).inspect_err(|_| {
        // Safety: switch_to_task_page_table failed, so task page table is not active.
        let _ = unsafe { delete_task_page_table(task_pt_id) };
    })?;

    // Load ldelf and TA - Box immediately to keep at fixed heap address
    let shim = litebox_shim_optee::OpteeShimBuilder::new().build();
    let loaded_program = Box::new(
        shim.load_ldelf(LDELF_BINARY, ta_uuid, Some(ta_bin))
            .map_err(|_| {
                // Safety: We are about to tear down this TA instance;
                // no references to user-space memory will be held afterwards.
                unsafe { teardown_ta_page_table(&shim, task_pt_id) };
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
    let ldelf_return_code: u32 = ldelf_ctx.rax.trunc();
    let ldelf_return_code =
        TeeResult::try_from(ldelf_return_code).unwrap_or(TeeResult::GenericError);
    if ldelf_return_code != TeeResult::Success {
        debug_serial_println!(
            "ldelf/TA_CreateEntryPoint failed: return_code={:?}",
            ldelf_return_code
        );

        // Write error response back to normal world
        let write_result = write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            ldelf_return_code,
            None, // No session ID on failure
            None,
            Some(ta_req_info),
        );

        // Safety: We are about to tear down this TA instance;
        // no references to user-space memory will be held afterwards.
        unsafe { teardown_ta_page_table(&shim, task_pt_id) };

        write_result?;
        return Ok(());
    }

    // Record the client identity before running OpenSession
    session_manager().set_session_client_identity(runner_session_id, client_identity);

    // Load TA context with parameters for OpenSession - pass actual session_id
    loaded_program.entrypoints.as_ref().ok_or_else(|| {
        // Safety: We are about to tear down this TA instance;
        // no references to user-space memory will be held afterwards.
        unsafe { teardown_ta_page_table(&shim, task_pt_id) };
        OpteeSmcReturnCode::EBadCmd
    })?;
    loaded_program
        .entrypoints
        .as_ref()
        .unwrap()
        .load_ta_context(
            params,
            runner_session_id,
            UteeEntryFunc::OpenSession as u32,
            None,
        )
        .map_err(|_| {
            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe { teardown_ta_page_table(&shim, task_pt_id) };
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
    let params_address = loaded_program.params_address.ok_or_else(|| {
        // Safety: We are about to tear down this TA instance;
        // no references to user-space memory will be held afterwards.
        unsafe { teardown_ta_page_table(&shim, task_pt_id) };
        OpteeSmcReturnCode::EBadAddr
    })?;
    let ta_params = UserConstPtr::<UteeParams>::from_usize(params_address)
        .read_at_offset(0)
        .ok_or_else(|| {
            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe { teardown_ta_page_table(&shim, task_pt_id) };
            OpteeSmcReturnCode::EBadAddr
        })?;

    // Check the return code from the TA's OpenSession entry point
    let return_code: u32 = ctx.rax.trunc();
    let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

    // Per OP-TEE OS: if OpenSession fails, tear down the instance
    // Reference: tee_ta_open_session() in tee_ta_manager.c
    if return_code != TeeResult::Success {
        debug_serial_println!(
            "OpenSession failed on new instance: return_code={:?}",
            return_code
        );

        // Write error response back to normal world
        let write_result = write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None, // No session ID on failure
            Some(&ta_params),
            Some(ta_req_info),
        );

        // Safety: We are about to tear down this TA instance;
        // no references to user-space memory will be held afterwards.
        unsafe { teardown_ta_page_table(&shim, task_pt_id) };

        write_result?;
        return Ok(());
    }

    // Write back BEFORE publishing the instance. If the write fails, the
    // session is neither registered nor cached, so we just tear down the
    // local resources and let `session_token` recycle the ID on drop.
    write_msg_args_to_normal_world(
        msg_args,
        msg_args_phys_addr,
        return_code,
        Some(runner_session_id),
        Some(&ta_params),
        Some(ta_req_info),
    )
    .inspect_err(|_| {
        // Safety: We are about to tear down this TA instance;
        // no references to user-space memory will be held afterwards.
        unsafe { teardown_ta_page_table(&shim, task_pt_id) };
    })?;

    // Success: register the new session with the manager.
    session_manager().register_new_session(
        runner_session_id,
        shim,
        loaded_program,
        task_pt_id,
        ta_uuid,
    );
    session_token.disarm();

    debug_serial_println!(
        "OpenSession complete: session_id={}, single_instance={}",
        runner_session_id,
        ta_flags.is_single_instance()
    );

    Ok(())
}

/// Tear down a `Dead` session entry observed at Invoke/Close handler entry.
///
/// Must be called from within a `with_session` closure so its serialization
/// covers the cleanup.
fn finalize_dead_session(
    session_id: u32,
    msg_args: &mut OpteeMsgArgs,
    msg_args_phys_addr: u64,
    return_code: TeeResult,
    log_prefix: &str,
) -> Result<(), OpteeSmcReturnCode> {
    session_manager().unregister_session(session_id);
    msg_args.ret = return_code;
    msg_args.ret_origin = TeeOrigin::Tee;
    write_non_ta_msg_args_to_normal_world(msg_args, msg_args_phys_addr)?;
    debug_serial_println!(
        "{}: session_id={} on dead TA session",
        log_prefix,
        session_id
    );
    Ok(())
}

/// Handle InvokeCommand.
///
/// Looks up the session by ID, switches to its page table, and runs the command.
///
/// Per OP-TEE OS semantics: if the TA panics (returns TARGET_DEAD), the session
/// should be cleaned up. For single-instance TAs, the entire instance is destroyed.
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

    session_manager().with_session(session_id, |instance| {
        let Some(instance) = instance else {
            return finalize_dead_session(
                session_id,
                msg_args,
                msg_args_phys_addr,
                TeeResult::TargetDead,
                "InvokeCommand",
            );
        };
        let task_pt_id = instance.task_page_table_id();

        let _task_pt_guard = TaskPageTableGuard::enter(task_pt_id)?;

        debug_serial_println!(
            "InvokeCommand: session_id={}, task_pt_id={}, cmd_id={}",
            session_id,
            task_pt_id,
            cmd_id
        );

        // Set up the entry-point parameters for InvokeCommand.
        let entrypoints_ref = instance.loaded_program().entrypoints.as_ref().unwrap();
        entrypoints_ref
            .load_ta_context(
                params.as_slice(),
                session_id,
                UteeEntryFunc::InvokeCommand as u32,
                Some(cmd_id),
            )
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        let mut ctx = litebox_common_linux::PtRegs::default();
        unsafe {
            litebox_platform_lvbs::reenter_thread_ref(
                instance.loaded_program().entrypoints.as_ref().unwrap(),
                &mut ctx,
            );
        }

        // params_address is constant - stack buffer is reused across invocations
        let params_address = instance
            .loaded_program()
            .params_address
            .ok_or(OpteeSmcReturnCode::EBadAddr)?;
        let ta_params = UserConstPtr::<UteeParams>::from_usize(params_address)
            .read_at_offset(0)
            .ok_or(OpteeSmcReturnCode::EBadAddr)?;

        let return_code: u32 = ctx.rax.trunc();
        let return_code = TeeResult::try_from(return_code).unwrap_or(TeeResult::GenericError);

        // Write response BEFORE switching page tables (accesses user memory).
        // `with_session`'s serialization keeps the entry stable so another core cannot
        // tear down the active page table while this core is copying TA outputs.
        let write_result = write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            return_code,
            None,
            Some(&ta_params),
            Some(&ta_req_info),
        );

        // Per OP-TEE OS: if TA panics (TARGET_DEAD), the TA context is
        // unrecoverable; all sessions on the same single-instance TA are
        // implicitly dead (Ref: tee_ta_invoke_command() in tee_ta_manager.c).
        if return_code == TeeResult::TargetDead {
            debug_serial_println!(
                "InvokeCommand: TA panicked (TARGET_DEAD), session_id={}",
                session_id
            );

            if instance.loaded_program().ta_flags.is_single_instance() {
                session_manager().mark_sessions_dead_for_instance(instance);
            }

            session_manager().unregister_session(session_id);

            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe {
                teardown_ta_page_table(instance.shim(), task_pt_id);
            };

            debug_serial_println!(
                "InvokeCommand: cleaned up dead TA instance, task_pt_id={}",
                task_pt_id
            );

            // TODO: Per OP-TEE OS semantics, if the TA has INSTANCE_KEEP_ALIVE but not
            // INSTANCE_KEEP_CRASHED, we should respawn the TA here instead of just
            // cleaning it up. Currently we always clean up on panic.
        }

        write_result
    })
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

    session_manager().with_session(session_id, |instance| {
        let Some(instance) = instance else {
            return finalize_dead_session(
                session_id,
                msg_args,
                msg_args_phys_addr,
                TeeResult::Success,
                "CloseSession",
            );
        };
        let task_pt_id = instance.task_page_table_id();

        let _task_pt_guard = TaskPageTableGuard::enter(task_pt_id)?;

        // Set up the entry-point parameters for CloseSession.
        instance
            .loaded_program()
            .entrypoints
            .as_ref()
            .unwrap()
            .load_ta_context(
                &[],
                session_id,
                UteeEntryFunc::CloseSession as u32,
                None,
            )
            .map_err(|_| OpteeSmcReturnCode::EBadCmd)?;

        // Run the TA entry function (TA_CloseSessionEntryPoint)
        let mut ctx = litebox_common_linux::PtRegs::default();
        unsafe {
            litebox_platform_lvbs::reenter_thread_ref(
                instance.loaded_program().entrypoints.as_ref().unwrap(),
                &mut ctx,
            );
        }

        // CloseSession always succeeds (TA_CloseSessionEntryPoint returns void)
        let write_result = write_msg_args_to_normal_world(
            msg_args,
            msg_args_phys_addr,
            TeeResult::Success,
            None,
            None,
            None,
        );

        let removed_flags = session_manager().unregister_session(session_id);

        let remaining_sessions = session_manager().count_sessions_for_instance(instance);

        // Last session on this instance — tear it down unless `keep_alive`
        // is set (only meaningful for single-instance TAs).
        if remaining_sessions == 0
            && let Some(flags) = removed_flags
        {
            if flags.is_single_instance() && flags.is_keep_alive() {
                debug_serial_println!(
                    "CloseSession complete: session_id={}, TA kept alive (INSTANCE_KEEP_ALIVE flag)",
                    session_id
                );
                return write_result;
            }

            // If this was a single-instance TA, clear the cached instance. This is safe because
            // we confirm no sibling sessions remain. We don't need to mark anything `Dead` first.
            if flags.is_single_instance() {
                let _ = session_manager()
                    .evict_cached_instance(instance);
            }
            // Safety: We are about to tear down this TA instance;
            // no references to user-space memory will be held afterwards.
            unsafe {
                teardown_ta_page_table(instance.shim(), task_pt_id);
            };

            debug_serial_println!(
                "CloseSession complete: deleted task_pt_id={} (last session)",
                task_pt_id
            );
        } else {
            debug_serial_println!(
                "CloseSession complete: session_id={}, other sessions remaining on TA",
                session_id
            );
        }

        write_result
    })
}

/// Update msg_args with return values and write back to normal world memory.
///
/// Serializes `OpteeMsgArgs` into a contiguous byte blob and writes it to
/// the VTL0 physical address.
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

    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);
    let mut blob = vec![0u8; msg_args_size];
    msg_args.serialize(&mut blob)?;

    let ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
        msg_args_phys_addr.trunc(),
        msg_args_size,
    )?;
    ptr.write_slice_at_offset(0, &blob)?;
    Ok(())
}

/// Write back `OpteeMsgArgs` for non-TA commands (e.g., RegisterShm, UnregisterShm) that
/// don't require TA userspace memory access.
///
/// Unlike [`write_msg_args_to_normal_world`], this function does not access TA userspace
/// memory and can be called from the base page table context. It simply serializes the
/// msg_args (which should already have `ret` / `ret_origin` set by the caller) back to
/// the normal world physical address.
#[inline]
fn write_non_ta_msg_args_to_normal_world(
    msg_args: &OpteeMsgArgs,
    msg_args_phys_addr: u64,
) -> Result<(), OpteeSmcReturnCode> {
    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);
    let mut blob = vec![0u8; msg_args_size];
    msg_args.serialize(&mut blob)?;

    let ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(
        msg_args_phys_addr.trunc(),
        msg_args_size,
    )?;
    ptr.write_slice_at_offset(0, &blob)?;
    Ok(())
}

/// Write `OpteeRpcArgs` to the normal world. Its write address is determined by
/// `msg_args_phys_addr` and the size of `OpteeMsgArgs`.
///
/// Unlike [`write_msg_args_to_normal_world`], this function does not access TA userspace
/// memory and can be called from the base page table context. It simply serializes the
/// rpc_args and writes it to the normal world physical address.
#[expect(dead_code)]
#[inline]
fn write_rpc_args_to_normal_world(
    msg_args: &OpteeMsgArgs,
    msg_args_phys_addr: u64,
    rpc_args: &OpteeRpcArgs,
) -> Result<(), OpteeSmcReturnCode> {
    let msg_args_size = optee_msg_args_total_size(msg_args.num_params);

    let rpc_args_size = optee_msg_args_total_size(rpc_args.num_params);
    let mut blob = vec![0u8; rpc_args_size];
    rpc_args.serialize(&mut blob)?;

    let rpc_pa: usize = <u64 as litebox::utils::TruncateExt<usize>>::trunc(msg_args_phys_addr)
        .checked_add(msg_args_size)
        .ok_or(OpteeSmcReturnCode::EBadAddr)?; // RPC args are placed right after the main msg_args blob
    let ptr = NormalWorldMutPtr::<u8, PAGE_SIZE>::with_contiguous_pages(rpc_pa, rpc_args_size)?;
    ptr.write_slice_at_offset(0, &blob)?;
    Ok(())
}

// use include_bytes! to include ldelf and (KMPP) TA binaries
const LDELF_BINARY: &[u8] = &[0u8; 0];
const TA_BINARY: &[u8] = &[0u8; 0];
const TA_BINARIES: &[&[u8]] = &[TA_BINARY];

/// Look up TA binary by UUID.
/// TODO: Handle PTA UUIDs
fn find_ta_binary(ta_uuid: litebox_common_optee::TeeUuid) -> Option<&'static [u8]> {
    use litebox_common_optee::parse_ta_head;

    for ta_binary in TA_BINARIES {
        if let Some(ta_head) = parse_ta_head(ta_binary)
            && ta_head.uuid == ta_uuid
        {
            return Some(ta_binary);
        }
    }
    None
}

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
