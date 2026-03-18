// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT thread creation and termination syscall handlers.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::NtShimEntrypoints;
use crate::handle_table::{NtObject, ThreadObject};
use litebox::platform::{RawConstPointer as _, ThreadProvider as _};
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

/// Sentinel return address pushed onto child thread stacks. When the start
/// routine returns, RIP becomes this value and faults. The exception handler
/// recognises this specific address as a clean thread exit (using RAX as exit
/// code) rather than a real crash. This value is in the null guard region
/// (first 64 KB) but distinct from 0, so it won't be confused with a null
/// function-pointer dereference.
pub(crate) const THREAD_EXIT_SENTINEL: usize = 0xDEAD;

// NtCreateThreadEx signature (simplified):
//   NTSTATUS NtCreateThreadEx(
//     OUT PHANDLE ThreadHandle,           // arg0 (r10)
//     IN ACCESS_MASK DesiredAccess,        // arg1 (rdx)
//     IN POBJECT_ATTRIBUTES ObjectAttributes, // arg2 (r8)
//     IN HANDLE ProcessHandle,             // arg3 (r9)
//     IN PVOID StartRoutine,               // [rsp+0x28]
//     IN PVOID Argument,                   // [rsp+0x30]
//     IN ULONG CreateFlags,                // [rsp+0x38]
//     IN SIZE_T ZeroBits,                  // [rsp+0x40]
//     IN SIZE_T StackSize,                 // [rsp+0x48]
//     IN SIZE_T MaximumStackSize,          // [rsp+0x50]
//     IN PPS_ATTRIBUTE_LIST AttributeList  // [rsp+0x58]
//   );

/// NtCreateThreadEx — create a new guest thread.
///
/// Allocates a new TEB, guest stack, sets up the execution context, and
/// spawns a platform thread via `ThreadProvider::spawn_thread`. The child
/// thread gets its own `NtShimEntrypoints` instance with shared process
/// state but independent handle table (seeded with stdio handles).
pub(crate) fn nt_create_thread_ex(
    ctx: &mut super::super::ExecutionContext,
    shim: &NtShimEntrypoints,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle_out_va = args.arg0;

    // Read stack arguments from guest stack.
    // Safety: guest VA is directly accessible in userland mode.
    let start_routine = unsafe { *((ctx.regs.rsp + 0x28) as *const usize) };
    let argument = unsafe { *((ctx.regs.rsp + 0x30) as *const usize) };
    let create_flags = unsafe { *((ctx.regs.rsp + 0x38) as *const u32) };
    let _zero_bits = unsafe { *((ctx.regs.rsp + 0x40) as *const usize) };
    let stack_size = unsafe { *((ctx.regs.rsp + 0x48) as *const usize) };
    let _max_stack_size = unsafe { *((ctx.regs.rsp + 0x50) as *const usize) };

    if (create_flags & 0x1) != 0 {
        log_unimplemented!("NtCreateThreadEx: CREATE_SUSPENDED not supported");
        return NtStatus::STATUS_NOT_IMPLEMENTED;
    }

    // Allocate a thread ID.
    let tid = {
        let mut id = shim.shared.next_thread_id.lock().unwrap();
        let val = *id;
        *id = val + 1;
        val
    };

    // Create the thread object (not yet inserted into handle table).
    let thread_obj = Arc::new(ThreadObject::new(tid));

    // Allocate guest stack for the new thread.
    let actual_stack_size = if stack_size == 0 {
        1024 * 1024 // 1 MiB default
    } else {
        (stack_size + 0xFFF) & !0xFFF
    };

    let pm = &shim.shared.process_state.pm;
    let nz_stack_size =
        litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(actual_stack_size)
            .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_stack_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let stack_base = match stack_base_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };
    let stack_top = stack_base + actual_stack_size;

    // Allocate a new TEB for the child thread (two pages — 8KB).
    let nz_teb_size = litebox::mm::linux::NonZeroPageSize::<{ crate::PAGE_SIZE }>::new(0x2000)
        .expect("TEB size must be page-aligned");
    let teb_ptr = unsafe {
        pm.create_writable_pages(
            None,
            nz_teb_size,
            litebox::mm::linux::CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    };
    let child_teb_va = match teb_ptr {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };

    // Initialize the child TEB by copying the parent's TEB and updating
    // thread-specific fields.
    let parent_teb_va = shim.init_state.as_ref().map_or(0, |s| s.teb_va);
    if parent_teb_va != 0 {
        // Safety: Both VAs are in guest address space, accessible in userland.
        unsafe {
            core::ptr::copy_nonoverlapping(
                parent_teb_va as *const u8,
                child_teb_va as *mut u8,
                0x2000,
            );
        }
    }
    // Update NtTib.Self at offset 0x30.
    unsafe {
        core::ptr::write((child_teb_va + 0x30) as *mut usize, child_teb_va);
    }
    // Update stack fields.
    unsafe {
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_BASE) as *mut usize,
            stack_top,
        );
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::STACK_LIMIT) as *mut usize,
            stack_base,
        );
    }
    // Zero TLS slots in child TEB (TlsSlots at offset 0x1480, 64 * 8 = 512 bytes).
    unsafe {
        core::ptr::write_bytes((child_teb_va + 0x1480) as *mut u8, 0, 64 * 8);
    }

    // Push the sentinel return address on the stack so that when the start
    // routine returns, the exception handler detects RIP == THREAD_EXIT_SENTINEL
    // and performs a clean thread exit with the return value as exit code.
    let rsp = stack_top - 8;
    unsafe {
        core::ptr::write(rsp as *mut usize, THREAD_EXIT_SENTINEL);
    }

    // Build a minimal execution context. The child's EnterShim::init() will
    // override RIP, RSP, and RCX before guest entry.
    let child_ctx = litebox_common_linux::ExecutionContext::default();

    // Get parent init state reference for child shim construction.
    let Some(parent_init) = &shim.init_state else {
        log_unimplemented!("NtCreateThreadEx: no parent init state");
        return NtStatus::STATUS_UNSUCCESSFUL;
    };

    // Create the child's shim entrypoints — shares all process-wide state.
    let child_shim = NtShimEntrypoints::new_for_child_thread(
        Arc::clone(&shim.shared),
        Arc::clone(&thread_obj),
        tid,
        parent_init,
        start_routine,
        rsp, // stack_top minus fake return address
        child_teb_va,
        argument,
    );

    // Wrap in InitThread for the platform.
    let init_args = Box::new(NtChildThreadInit {
        child_shim,
        child_teb_va,
    });

    // Spawn the thread.
    let platform = litebox_platform_multiplex::platform();
    if unsafe { platform.spawn_thread(&child_ctx, init_args) }.is_err() {
        log_unimplemented!("NtCreateThreadEx: spawn_thread failed");
        return NtStatus::STATUS_NO_MEMORY;
    }

    // Thread spawned successfully — now insert handle into the shared table.
    // This is deferred so that error paths above don't leave a dangling handle
    // for a thread that never started.
    let handle = shim
        .shared
        .handles
        .lock()
        .unwrap()
        .insert(NtObject::Thread(Arc::clone(&thread_obj)));

    // Write the handle to the caller's output.
    if handle_out_va != 0 {
        // Safety: guest VA directly accessible.
        unsafe {
            core::ptr::write(handle_out_va as *mut u32, handle);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// InitThread implementation for child NT threads.
///
/// Carries the fully-configured child `NtShimEntrypoints` and the child TEB VA.
/// When `init()` is called on the new host thread, it sets the GS base and
/// returns the child shim as the `EnterShim` for the thread's execution loop.
struct NtChildThreadInit {
    child_shim: NtShimEntrypoints,
    child_teb_va: usize,
}

// Safety: NtShimEntrypoints fields are all Send+Sync (Mutex, Arc, Atomic).
// ThreadObject is Arc-wrapped. child_teb_va is a plain usize.
unsafe impl Send for NtChildThreadInit {}

impl litebox::shim::InitThread for NtChildThreadInit {
    type ExecutionContext = litebox_common_linux::ExecutionContext;

    fn init(
        self: alloc::boxed::Box<Self>,
    ) -> alloc::boxed::Box<dyn litebox::shim::EnterShim<ExecutionContext = Self::ExecutionContext>>
    {
        // Set GS base for this host thread to point to the child TEB.
        // This must happen on the new thread (TLS is per-thread).
        litebox_platform_windows_userland::WindowsUserland::set_guest_gs_base(
            self.child_teb_va as u64,
        );

        // Return the child's shim entrypoints. Its init() will set RIP, RSP,
        // and RCX correctly for child thread entry.
        Box::new(self.child_shim)
    }
}

/// NtTerminateThread — terminate the current thread.
///
/// Returns (status, should_terminate). When should_terminate is true, the
/// platform will exit the thread's execution loop.
pub(crate) fn nt_terminate_thread(ctx: &mut super::super::ExecutionContext) -> (NtStatus, bool) {
    let _args = NtSyscallArgs::from_ctx(ctx);
    // args.arg0 = handle (-2 = current thread)
    // args.arg1 = exit code

    // For now, only support terminating the current thread.
    (NtStatus::STATUS_SUCCESS, true)
}
