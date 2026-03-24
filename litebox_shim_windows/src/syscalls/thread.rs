// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT thread creation and termination syscall handlers.

use alloc::boxed::Box;
use alloc::sync::Arc;

use crate::NtShimEntrypoints;
use crate::handle_table::{NtObject, ThreadObject};
use litebox::platform::{RawConstPointer as _, RawPointerProvider, ThreadProvider as _};
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn set_guest_gs_base(value: u64) {
    litebox_platform_windows_userland::WindowsUserland::set_guest_gs_base(value);
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn set_guest_gs_base(_value: u64) {}

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

    let unsupported_flags = create_flags & !0x1;
    if unsupported_flags != 0 {
        log_unimplemented!("NtCreateThreadEx: unsupported create_flags=0x{create_flags:X}");
        return NtStatus::STATUS_NOT_IMPLEMENTED;
    }
    let initial_suspend_count = u32::from((create_flags & 0x1) != 0);

    // Allocate a thread ID.
    let tid = {
        let mut id = shim.shared.next_thread_id.lock();
        let val = *id;
        *id = val + crate::peb_teb::SYNTHETIC_THREAD_ID_INCREMENT;
        val
    };

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
    let cleanup_stack = |stack_base: usize| {
        let stack_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(stack_base);
        let _ = unsafe { pm.remove_pages(stack_ptr, actual_stack_size) };
    };

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
        Err(_) => {
            cleanup_stack(stack_base);
            return NtStatus::STATUS_NO_MEMORY;
        }
    };
    let cleanup_stack_and_teb = || {
        super::section::free_thread_tls_allocations(&shim.shared, child_teb_va);
        let teb_ptr = <litebox_platform_multiplex::Platform as RawPointerProvider>::RawMutPointer::<
            u8,
        >::from_usize(child_teb_va);
        let _ = unsafe { pm.remove_pages(teb_ptr, 0x2000) };
        cleanup_stack(stack_base);
    };

    // Create the thread object once the child TEB VA is known.
    let thread_obj = Arc::new(ThreadObject::new(tid, initial_suspend_count, child_teb_va));
    let Some(parent_init) = &shim.init_state else {
        log_unimplemented!("NtCreateThreadEx: no parent init state");
        cleanup_stack_and_teb();
        return NtStatus::STATUS_UNSUCCESSFUL;
    };

    // Initialize the child TEB by copying the parent's TEB and updating
    // thread-specific fields.
    let parent_teb_va = parent_init.teb_va;
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
    // Update ClientId.UniqueThread to the guest-visible thread ID.
    unsafe {
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::CLIENT_ID_THREAD) as *mut u64,
            u64::from(tid),
        );
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
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::DEALLOCATION_STACK) as *mut usize,
            stack_base,
        );
    }
    // Child threads must not inherit the parent's TLS bookkeeping pointers or
    // inline slots; module TLS blocks are per-thread.
    unsafe {
        core::ptr::write(
            (child_teb_va + crate::peb_teb::teb_offsets::TLS_POINTER) as *mut usize,
            0,
        );
        core::ptr::write((child_teb_va + 0x1780) as *mut usize, 0);
        core::ptr::write_bytes((child_teb_va + 0x1480) as *mut u8, 0, 64 * 8);
    }
    super::section::initialize_static_tls_for_teb(&shim.shared, child_teb_va);

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
    shim.shared
        .threads_by_id
        .lock()
        .insert(tid, Arc::clone(&thread_obj));
    if unsafe { platform.spawn_thread(&child_ctx, init_args) }.is_err() {
        shim.shared.threads_by_id.lock().remove(&tid);
        cleanup_stack_and_teb();
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
        set_guest_gs_base(self.child_teb_va as u64);

        if let Some(thread_obj) = self.child_shim.thread_obj.as_ref() {
            thread_obj.wait_until_resumed(&self.child_shim.wait_cx());
        }

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
