// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT syscall handler implementations.
//!
//! Each handler receives the execution context and returns an `NtStatus`.
//! Arguments are read from the Windows x64 syscall convention registers:
//! - r10: arg0, rdx: arg1, r8: arg2, r9: arg3

use crate::handle_table::{HandleTable, NtObject};
use litebox_common_windows::ntstatus::NtStatus;

pub(crate) mod file;
pub(crate) mod heap;
pub(crate) mod k32_handlers;
pub(crate) mod memory;
pub(crate) mod sysinfo;

/// Helper to read NT syscall arguments from the execution context.
pub(crate) struct NtSyscallArgs {
    pub arg0: usize, // r10
    pub arg1: usize, // rdx
    pub arg2: usize, // r8
    pub arg3: usize, // r9
}

impl NtSyscallArgs {
    pub fn from_ctx(ctx: &super::ExecutionContext) -> Self {
        Self {
            arg0: ctx.regs.r10,
            arg1: ctx.regs.rdx,
            arg2: ctx.regs.r8,
            arg3: ctx.regs.r9,
        }
    }
}

/// NtClose — close a handle.
pub(crate) fn nt_close(handles: &mut HandleTable, handle: u32) -> NtStatus {
    if handles.close(handle).is_some() {
        NtStatus::STATUS_SUCCESS
    } else {
        NtStatus::STATUS_INVALID_HANDLE
    }
}

/// Handle kernel32 GetStdHandle syscall.
///
/// Args: r10 = nStdHandle (DWORD).
/// Returns: handle value in rax (not an NTSTATUS).
pub(crate) fn k32_get_std_handle(
    ctx: &mut super::ExecutionContext,
    stdin_h: u32,
    stdout_h: u32,
    stderr_h: u32,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let which = args.arg0 as u32;

    let handle = match which {
        litebox_common_windows::STD_INPUT_HANDLE => stdin_h,
        litebox_common_windows::STD_OUTPUT_HANDLE => stdout_h,
        litebox_common_windows::STD_ERROR_HANDLE => stderr_h,
        _ => return NtStatus::STATUS_INVALID_PARAMETER,
    };

    ctx.regs.rax = handle as usize;
    NtStatus::STATUS_SUCCESS
}

/// Handle kernel32 WriteConsoleA syscall.
///
/// Args: r10 = hConsoleOutput, rdx = lpBuffer, r8 = nNumberOfCharsToWrite,
///       r9 = lpNumberOfCharsWritten
pub(crate) fn k32_write_console_a(
    ctx: &mut super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let buffer_va = args.arg1;
    let count = args.arg2;
    let written_va = args.arg3;

    match handles.get(handle) {
        Some(NtObject::ConsoleOutput { .. }) => {
            if buffer_va != 0 && count > 0 {
                // Safety: On userland, guest VA is directly accessible.
                unsafe {
                    let buf = core::slice::from_raw_parts(buffer_va as *const u8, count);
                    use litebox::platform::DebugLogProvider as _;
                    if let Ok(s) = core::str::from_utf8(buf) {
                        litebox_platform_multiplex::platform().debug_log_print(s);
                    } else {
                        litebox_platform_multiplex::platform()
                            .debug_log_print("<non-UTF8 console output>\n");
                    }
                }
                if written_va != 0 {
                    unsafe {
                        core::ptr::write(written_va as *mut u32, count as u32);
                    }
                }
            }
            ctx.regs.rax = 1;
            NtStatus::STATUS_SUCCESS
        }
        _ => NtStatus::STATUS_INVALID_HANDLE,
    }
}

/// Handle kernel32 WriteConsoleW syscall.
///
/// Args: r10 = hConsoleOutput, rdx = lpBuffer (UTF-16LE), r8 = nNumberOfCharsToWrite,
///       r9 = lpNumberOfCharsWritten
pub(crate) fn k32_write_console_w(
    ctx: &mut super::ExecutionContext,
    handles: &HandleTable,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let handle = args.arg0 as u32;
    let buffer_va = args.arg1;
    let char_count = args.arg2;
    let written_va = args.arg3;

    match handles.get(handle) {
        Some(NtObject::ConsoleOutput { .. }) => {
            if buffer_va != 0 && char_count > 0 {
                unsafe {
                    let wchars = core::slice::from_raw_parts(buffer_va as *const u16, char_count);
                    let s: alloc::string::String = alloc::string::String::from_utf16_lossy(wchars);
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&s);
                }
                if written_va != 0 {
                    unsafe {
                        core::ptr::write(written_va as *mut u32, char_count as u32);
                    }
                }
            }
            ctx.regs.rax = 1;
            NtStatus::STATUS_SUCCESS
        }
        _ => NtStatus::STATUS_INVALID_HANDLE,
    }
}

/// Handle kernel32 ExitProcess syscall.
///
/// Args: r10 = uExitCode
pub(crate) fn k32_exit_process(ctx: &mut super::ExecutionContext) -> (NtStatus, bool, i32) {
    let args = NtSyscallArgs::from_ctx(ctx);
    let exit_code = args.arg0 as i32;
    (NtStatus::STATUS_SUCCESS, true, exit_code)
}
