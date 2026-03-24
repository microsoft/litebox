// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Minimal Win32k / CSR handlers for USER32/GDI32 initialization.
//!
//! We don't implement the full Win32k subsystem.  We provide just enough
//! for USER32.dll's DllMain (`UserClientDllInitialize`) to succeed.
//!
//! ## `CsrClientConnectToServer` (pseudo-syscall 0x2000)
//!
//! USER32's `_UserClientDllInitialize` calls `CsrClientConnectToServer`
//! (an ntdll function, not a win32k syscall) with `ServerDllIndex = 3`
//! (USER subsystem).  In real Windows this establishes an LPC/ALPC
//! connection to CSRSS and returns a SHAREDINFO structure in the
//! ConnectionInformation output buffer.  USER32 then copies that buffer
//! (0x248 bytes) into the global `gSharedInfo`.
//!
//! In our sandbox there is no CSRSS, so we patch `CsrClientConnectToServer`
//! into a pseudo-syscall that jumps through the trampoline to the shim.
//! The handler below allocates a minimal SERVERINFO page and fills in the
//! ConnectionInformation buffer so that `gSharedInfo.psi` is non-NULL.
//!
//! ## `NtGdiInit` / `NtGdiInit2` (win32k syscalls 0x12E7 / 0x12E8)
//!
//! `gdi32full!GdiDllInitialize_OLD` calls `NtGdiInit2` to establish the
//! per-process GDI connection.  The return value is a non-NULL "cookie"
//! stored in `gCookie`.  If `NtGdiInit2` returns NULL, GdiDllInitialize
//! fails, which in turn causes USER32's DllMain to return FALSE.
//!
//! `GdiProcessSetup` later calls `NtGdiInit` for further GDI state setup.
//! Both return opaque handles/pointers that are used in subsequent GDI
//! calls.  In our sandbox we allocate dummy pages so the pointers are
//! valid but all fields are zero (no GDI rendering capability).

use alloc::sync::Arc;

use litebox::mm::linux::{CreatePagesFlags, NonZeroPageSize};
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;
use crate::{NtProcessState, PAGE_SIZE};

/// NtUserProcessConnect — establish Win32k subsystem connection.
///
/// Signature:
/// ```text
/// NTSTATUS NtUserProcessConnect(
///     HANDLE ProcessHandle,    // r10 (ignored)
///     PVOID  pUserConnect,     // rdx — output buffer
///     ULONG  UserConnectSize   // r8  — buffer size (usually 0x88)
/// );
/// ```
///
/// USER32's `UserClientDllInitialize` reads the connection output to set
/// `gSharedInfo` and `gpsi`.  We allocate a zero-filled page as a minimal
/// SHAREDINFO structure.  All-zeros means "no capabilities / no IMM /
/// headless" which is exactly what we want for a sandboxed console process.
pub(crate) fn nt_user_process_connect(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    const USER_CONNECT_MIN_SIZE: usize = 0x20;

    let args = NtSyscallArgs::from_ctx(ctx);
    let user_connect_ptr = args.arg1; // rdx
    let user_connect_size = args.arg2 as usize; // r8

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserProcessConnect(buf=0x{:X}, size=0x{:X})\n",
            user_connect_ptr,
            user_connect_size,
        ));
    }

    if user_connect_ptr == 0 || user_connect_size < USER_CONNECT_MIN_SIZE {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    // Allocate a zero-filled page for the SHAREDINFO / SERVERINFO structure.
    // USER32 will store this pointer in gSharedInfo.  Since all fields are
    // zero, USER32 treats it as "no Win32k capabilities" and skips IMM init.
    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE) else {
        return NtStatus::STATUS_NO_MEMORY;
    };
    let shared_info_va = match unsafe {
        process_state.pm.create_writable_pages(
            None,
            nz_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    } {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };

    // Zero-fill the output buffer.
    // Safety: user_connect_ptr was validated non-zero above and the guest
    // memory at that address was set up by USER32 before invoking the syscall.
    unsafe {
        core::ptr::write_bytes(user_connect_ptr as *mut u8, 0, user_connect_size);
    }

    // USERCONNECT_INFO layout (reverse-engineered from USER32 init):
    //   offset 0x00: ulVersion (ULONG) — connection protocol version
    //   offset 0x08: pSharedInfo (PVOID) — pointer to SHAREDINFO
    //   offset 0x10: pServerInfo (PVOID) — pointer to SERVERINFO (psi)
    //   ... other fields ...
    //
    // USER32's init code does approximately:
    //   gSharedInfo = pUserConnect->pSharedInfo;
    //   gpsi = gSharedInfo->psi;
    //
    // We set pSharedInfo to our zero-filled page and populate a few pointer
    // fields so that regardless of which exact offset USER32 reads, it gets
    // a valid (non-NULL) pointer.

    // Safety: the buffer is guest-mapped and large enough for the 0x20-byte
    // prefix we populate below.
    unsafe {
        let buf = user_connect_ptr as *mut u64;
        // offset 0x00: version field (Win Vista+)
        core::ptr::write(buf, 0x0600);
        // offset 0x08: SHAREDINFO pointer
        core::ptr::write(buf.add(1), shared_info_va as u64);
        // offset 0x10: another pointer (sometimes pDesktopInfo)
        core::ptr::write(buf.add(2), shared_info_va as u64);
        // offset 0x18: yet another pointer
        core::ptr::write(buf.add(3), shared_info_va as u64);

        // Inside the SHAREDINFO structure:
        //   +0x00: dwFlags  — leave as 0 (no capabilities)
        //   +0x08: psi (SERVERINFO pointer) — point within our page
        let si = shared_info_va as *mut u64;
        core::ptr::write(si.add(1), (shared_info_va + 0x100) as u64);
        // +0x10: aheList (USER handle table) — leave as NULL; USER32
        //        checks for NULL before use.
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtUserProcessConnect → shared_info at 0x{:X}\n",
            shared_info_va,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtGdiInit2` — win32k syscall 0x12E8.
///
/// Called by `gdi32full!GdiDllInitialize_OLD` to establish the per-process
/// GDI connection.  Returns an opaque "cookie" pointer stored in `gCookie`.
/// If the return is NULL, `GdiDllInitialize_OLD` fails, which causes USER32's
/// `_UserClientDllInitialize` to return FALSE (DLL init failure).
///
/// In our sandbox we allocate a zero-filled page and return its address as
/// the cookie.  All-zeros means "no GDI rendering state", which is correct
/// for a headless console sandbox.
pub(crate) fn nt_gdi_init2(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE) else {
        return NtStatus::STATUS_NO_MEMORY;
    };
    let cookie_va = match unsafe {
        process_state.pm.create_writable_pages(
            None,
            nz_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    } {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };

    ctx.regs.rax = cookie_va;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtGdiInit2 → cookie at 0x{:X}\n",
            cookie_va,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `NtGdiInit` — win32k syscall 0x12E7.
///
/// Called by `gdi32full!GdiProcessSetup` during GDI initialization.
/// Returns a handle/pointer to GDI shared memory.  We return a dummy
/// non-NULL pointer (same pattern as `NtGdiInit2`).
pub(crate) fn nt_gdi_init(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE) else {
        return NtStatus::STATUS_NO_MEMORY;
    };
    let gdi_shared_va = match unsafe {
        process_state.pm.create_writable_pages(
            None,
            nz_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_| Ok(0),
        )
    } {
        Ok(ptr) => ptr.as_usize(),
        Err(_) => return NtStatus::STATUS_NO_MEMORY,
    };

    ctx.regs.rax = gdi_shared_va;

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: NtGdiInit → gdi_shared at 0x{:X}\n",
            gdi_shared_va,
        ));
    }

    NtStatus::STATUS_SUCCESS
}

/// `CsrClientConnectToServer` pseudo-syscall handler.
///
/// Signature (Windows x64 calling convention, captured via trampoline):
/// ```text
/// NTSTATUS CsrClientConnectToServer(
///     PWSTR  ObjectDirectory,              // r10 (moved from rcx)
///     ULONG  ServerDllIndex,               // rdx
///     PVOID  ConnectionInformation,        // r8  — output buffer
///     ULONG  ConnectionInformationLength,  // r9
///     PBOOLEAN CalledFromServer            // [rsp+0x28]
/// );
/// ```
///
/// For `ServerDllIndex == 3` (USER subsystem), USER32 copies the entire
/// `ConnectionInformation` buffer (0x248 bytes) into `gSharedInfo`.
/// The first QWORD of that buffer must be a valid `psi` (SERVERINFO
/// pointer) or USER32's init code will crash on `test byte [psi], 4`.
///
/// We allocate a zero-filled SERVERINFO page and write its address into
/// `ConnectionInformation[0]`.  Zero flags in SERVERINFO means "no Win32k
/// capabilities / headless" — exactly right for sandboxed console apps.
pub(crate) fn csr_client_connect_to_server(
    ctx: &mut crate::ExecutionContext,
    process_state: &Arc<NtProcessState>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _object_directory = args.arg0; // r10 — not used
    let server_dll_index = args.arg1 as u32; // rdx
    let conn_info_ptr = args.arg2; // r8
    let conn_info_len = args.arg3; // r9 — length value

    if conn_info_ptr == 0 {
        return NtStatus::STATUS_INVALID_PARAMETER;
    }

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "NT shim: CsrClientConnectToServer(server={}, buf=0x{:X}, len=0x{:X})\n",
            server_dll_index,
            conn_info_ptr,
            conn_info_len,
        ));
    }

    // The 5th arg (CalledFromServer) is a pointer to BOOLEAN in USER32's
    // `gfServerProcess`.  It's zero-initialized (.bss), so we don't need
    // to write to it — FALSE (0) is already the correct value.

    // Zero the output buffer for all subsystem indices.
    let buf_size = conn_info_len.min(0x1000); // cap at one page
    if buf_size > 0 {
        unsafe {
            core::ptr::write_bytes(conn_info_ptr as *mut u8, 0, buf_size);
        }
    }

    // For the USER subsystem (index 3), fill in a minimal SERVERINFO
    // so that gSharedInfo.psi (= gpsi) is non-NULL.
    //
    // Buffer layout observed from real CsrClientConnectToServer via cdb:
    //   +0x00: ulVersion / flags (DWORD, not copied into gSharedInfo)
    //   +0x08: psi (PSERVERINFO) — becomes gSharedInfo[0] = gpsi
    //   +0x10: desktop heap ptr  — becomes gSharedInfo[1]
    //   +0x18: cbHandleEntry     — becomes gSharedInfo[2]
    //   +0x20: aheList           — becomes gSharedInfo[3]
    //   ...
    //
    // USER32 copies buffer[0x08..0x248] (0x240 bytes) into gSharedInfo.
    // Then: gpsi = gSharedInfo[0]; test byte [gpsi], 4.
    if server_dll_index == 3 {
        // Allocate a zero-filled page for the SERVERINFO structure.
        let Some(nz_size) = NonZeroPageSize::<PAGE_SIZE>::new(PAGE_SIZE) else {
            return NtStatus::STATUS_NO_MEMORY;
        };
        let server_info_va = match unsafe {
            process_state.pm.create_writable_pages(
                None,
                nz_size,
                CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
                |_| Ok(0),
            )
        } {
            Ok(ptr) => ptr.as_usize(),
            Err(_) => return NtStatus::STATUS_NO_MEMORY,
        };

        // Populate SERVERINFO.dwSRVIFlags at the start of the page.
        // Real Windows has 0x0d14 here.  USER32 checks `test byte [gpsi], 4`
        // (bit 2 = SRVIF_*); if set, it initializes IMM.  We clear bit 2
        // to skip IMM init since the sandbox has no IME support.
        // The remaining flags (0x0d10) still look reasonable.
        unsafe {
            core::ptr::write(server_info_va as *mut u32, 0x0d10_u32);
        }

        // Write psi at buffer+0x08 (NOT +0x00).
        if buf_size >= 0x10 {
            unsafe {
                let buf = conn_info_ptr as *mut u64;
                // +0x08: SERVERINFO pointer → gSharedInfo[0] = gpsi
                core::ptr::write(buf.add(1), server_info_va as u64);
            }
        }

        #[cfg(debug_assertions)]
        {
            use litebox::platform::DebugLogProvider as _;
            litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                "NT shim: CsrClientConnectToServer(USER) → SERVERINFO at 0x{:X}, buf_size=0x{:X}\n",
                server_info_va,
                buf_size,
            ));
        }
    }

    NtStatus::STATUS_SUCCESS
}
