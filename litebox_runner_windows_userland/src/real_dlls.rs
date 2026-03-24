// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real-DLL loader for the Windows userland runner.
//!
//! Loads real System32 DLLs (ntdll.dll with rewritten syscalls,
//! kernel32.dll, ucrtbase.dll, etc.) from a pre-built tar file into
//! the guest address space. The ntdll syscall stubs are rewritten
//! to jump to the litebox shim, while all other DLL code runs
//! natively — matching the Linux approach where real shared libraries
//! run unmodified and only the syscall entry points are intercepted.

use std::collections::BTreeMap;

use crate::PmMapper;

use anyhow::{Result, anyhow};
use litebox_common_windows::ntdll_rewriter;
use litebox_common_windows::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION;
use litebox_common_windows::pe_loader::{IatPatch, LoadedModule, load_pe};
use litebox_common_windows::pe_parser::PeParsedFile;

/// Read an entire file from VFS into a `Vec<u8>`.
///
/// Opens the file at `path`, queries its size, reads it, and closes the fd.
pub fn read_vfs_file(fs: &litebox_shim_windows::NtFS, path: &str) -> Result<Vec<u8>> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(path, litebox::fs::OFlags::RDONLY, litebox::fs::Mode::RUSR)
        .map_err(|e| anyhow!("VFS open {path:?}: {e:?}"))?;
    let size = fs.fd_file_status(&fd).map(|s| s.size).unwrap_or(0);
    let mut buf = vec![0u8; size];
    let n = fs.read(&fd, &mut buf, None).unwrap_or(0);
    buf.truncate(n);
    let _ = fs.close(&fd);
    if buf.is_empty() {
        return Err(anyhow!("VFS file {path:?} is empty or unreadable"));
    }
    Ok(buf)
}

/// Find a file in VFS by its basename (case-insensitive) under `dir_path`.
///
/// Lists the directory entries and returns the full VFS path of the first
/// file whose name matches `target_name` (case-insensitive).
pub fn find_vfs_file(
    fs: &litebox_shim_windows::NtFS,
    dir_path: &str,
    target_name: &str,
) -> Option<String> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(
            dir_path,
            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
            litebox::fs::Mode::RUSR,
        )
        .ok()?;
    let entries = fs.read_dir(&fd).ok()?;
    let _ = fs.close(&fd);

    let target_lower = target_name.to_ascii_lowercase();
    for entry in &entries {
        if entry.name.to_ascii_lowercase() == target_lower {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            return Some(format!("{dir_path}{sep}{}", entry.name));
        }
    }
    None
}

/// Find a file anywhere in the VFS by searching known directories,
/// then falling back to a recursive search from the root.
///
/// Searches root (`/`) and common Windows paths first for `filename`,
/// then recursively searches the entire VFS tree.
pub fn find_vfs_file_by_name(fs: &litebox_shim_windows::NtFS, filename: &str) -> Option<String> {
    // Search directories in priority order: root, then Windows System32 paths.
    let search_dirs = ["/", "/c/windows/system32", "/c/windows"];
    for dir in &search_dirs {
        if let Some(path) = find_vfs_file(fs, dir, filename) {
            return Some(path);
        }
    }
    // Fall back to recursive search from root.
    find_vfs_file_recursive(fs, "/", filename)
}

/// Recursively search a VFS directory tree for a file by basename suffix
/// (case-insensitive). Returns the full VFS path if found.
fn find_vfs_file_recursive(
    fs: &litebox_shim_windows::NtFS,
    dir_path: &str,
    target_suffix: &str,
) -> Option<String> {
    use litebox::fs::FileSystem as _;

    let fd = fs
        .open(
            dir_path,
            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
            litebox::fs::Mode::RUSR,
        )
        .ok()?;
    let entries = fs.read_dir(&fd).ok()?;
    let _ = fs.close(&fd);

    let target_lower = target_suffix.to_ascii_lowercase();
    let mut subdirs = Vec::new();

    for entry in &entries {
        let name_lower = entry.name.to_ascii_lowercase();
        if name_lower.ends_with(&target_lower)
            && entry.file_type != litebox::fs::FileType::Directory
        {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            return Some(format!("{dir_path}{sep}{}", entry.name));
        }
        // Collect subdirectories for recursive search using VFS metadata.
        // Skip "." and ".." to avoid infinite recursion.
        if entry.file_type == litebox::fs::FileType::Directory
            && entry.name != "."
            && entry.name != ".."
        {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            subdirs.push(format!("{dir_path}{sep}{}", entry.name));
        }
    }

    // Recurse into subdirectories.
    for subdir in subdirs {
        if let Some(found) = find_vfs_file_recursive(fs, &subdir, target_suffix) {
            return Some(found);
        }
    }
    None
}

/// Information about a loaded DLL in guest memory.
#[allow(dead_code)]
pub struct LoadedDll {
    pub name: String,
    pub base_address: usize,
    pub image_size: usize,
    pub entry_point: usize,
    pub pe_data: Vec<u8>,
    pub has_entry_point: bool,
}

/// Result of loading ntdll for the ntdll-driven init approach.
///
/// Only ntdll is loaded and rewritten. The ntdll loader (LdrpInitialize)
/// will load all other DLLs via syscalls, which the shim intercepts and
/// serves from the tar file.
pub struct NtdllInitLoadResult {
    /// The loaded ntdll DLL info.
    pub ntdll: LoadedDll,
    /// The trampoline page bytes (must be mapped at `trampoline_va`).
    pub trampoline: Vec<u8>,
    /// VA where the trampoline should be mapped.
    pub trampoline_va: usize,
    /// Offset within trampoline where the shim entry pointer goes.
    pub entry_ptr_offset: usize,
    /// Offset within trampoline where the forward GS table pointer goes.
    pub gs_table_ptr_offset: usize,
    /// Offset within trampoline where the reverse GS table pointer goes.
    pub reverse_gs_table_ptr_offset: usize,
    /// Number of ntdll syscall stubs that were rewritten.
    #[allow(dead_code)]
    pub stubs_rewritten: usize,
    /// Number of stubs whose syscall number was identified (matched export name).
    #[allow(dead_code)]
    pub stubs_identified: usize,
    /// VA of ntdll!LdrInitializeThunk (thread entry point).
    pub ldr_init_thunk_va: usize,
    /// VA of ntdll!RtlUserThreadStart (for CONTEXT.Rip after init).
    pub rtl_user_thread_start_va: usize,
    /// Mapping from real Windows syscall numbers to NtSyscallId.
    pub syscall_map: litebox_common_windows::NtSyscallMap,
    /// Syscall number → export name for stubs not in NtSyscallId (for debug logging).
    pub unhandled_stubs: Vec<(u32, String)>,
    /// RVA of KiUserExceptionDispatcher in ntdll (for SEH dispatch).
    pub ki_user_exception_dispatcher_rva: Option<usize>,
    /// Guest VA of `ntdll!KiUserInvertedFunctionTable`.  The shim uses this
    /// to register loaded DLLs so SEH unwinding finds their .pdata.
    pub inverted_function_table_va: usize,
    /// Guest VA of `ntdll!LdrpHashTable`.
    pub ldrp_hash_table_va: usize,
    /// Guest VA of `ntdll!PebLdr`.
    pub pebldr_va: usize,
}

fn find_ntdll_hash_table_va(parsed: &PeParsedFile, image_base: usize) -> Result<usize> {
    let text = parsed
        .sections
        .iter()
        .find(|s| s.name.starts_with(b".text"))
        .ok_or_else(|| anyhow!("ntdll missing .text section"))?;

    // 41 83 E5 1F                and r13d, 1Fh
    // 48 8D 05 xx xx xx xx       lea rax, [rip+disp32]  ; LdrpHashTable
    // 49 C1 E5 04                shl r13, 4
    // 4C 03 E8                   add r13, rax
    // 4D 8B 7D 00                mov r15, [r13]
    // 4D 3B FD                   cmp r15, r13
    const PATTERN: [Option<u8>; 25] = [
        Some(0x41),
        Some(0x83),
        Some(0xE5),
        Some(0x1F),
        Some(0x48),
        Some(0x8D),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x49),
        Some(0xC1),
        Some(0xE5),
        Some(0x04),
        Some(0x4C),
        Some(0x03),
        Some(0xE8),
        Some(0x4D),
        Some(0x8B),
        Some(0x7D),
        Some(0x00),
        Some(0x4D),
        Some(0x3B),
        Some(0xFD),
    ];

    let text_va = image_base + text.virtual_address as usize;
    let text_len = text.virtual_size.max(text.size_of_raw_data) as usize;
    let text_bytes = unsafe { core::slice::from_raw_parts(text_va as *const u8, text_len) };

    let mut match_va = None;
    for off in 0..=text_bytes.len().saturating_sub(PATTERN.len()) {
        let matched = PATTERN
            .iter()
            .enumerate()
            .all(|(i, byte)| byte.is_none_or(|b| text_bytes[off + i] == b));
        if !matched {
            continue;
        }

        if match_va.is_some() {
            anyhow::bail!("ntdll LdrpHashTable signature matched multiple locations");
        }

        let disp = i32::from_le_bytes(text_bytes[off + 7..off + 11].try_into().unwrap()) as isize;
        let lea_next_rip = (text_va + off + 11) as isize;
        match_va = Some((lea_next_rip + disp) as usize);
    }

    match_va.ok_or_else(|| anyhow!("failed to locate ntdll!LdrpHashTable"))
}

fn find_ntdll_pebldr_va(parsed: &PeParsedFile, image_base: usize) -> Result<usize> {
    let text = parsed
        .sections
        .iter()
        .find(|s| s.name.starts_with(b".text"))
        .ok_or_else(|| anyhow!("ntdll missing .text section"))?;

    // 48 8B 3D xx xx xx xx       mov rdi, [rip+disp32]  ; PebLdr+0x10
    // BB 01 00 00 00             mov ebx, 1
    // 83 64 24 60 00             and dword ptr [rsp+60h], 0
    // 48 8D 05 yy yy yy yy       lea rax, [rip+disp32]  ; PebLdr+0x10
    // 48 3B F8                   cmp rdi, rax
    const PATTERN: [Option<u8>; 27] = [
        Some(0x48),
        Some(0x8B),
        Some(0x3D),
        None,
        None,
        None,
        None,
        Some(0xBB),
        Some(0x01),
        Some(0x00),
        Some(0x00),
        Some(0x00),
        Some(0x83),
        Some(0x64),
        Some(0x24),
        Some(0x60),
        Some(0x00),
        Some(0x48),
        Some(0x8D),
        Some(0x05),
        None,
        None,
        None,
        None,
        Some(0x48),
        Some(0x3B),
        Some(0xF8),
    ];

    let text_va = image_base + text.virtual_address as usize;
    let text_len = text.virtual_size.max(text.size_of_raw_data) as usize;
    let text_bytes = unsafe { core::slice::from_raw_parts(text_va as *const u8, text_len) };

    let mut match_va = None;
    for off in 0..=text_bytes.len().saturating_sub(PATTERN.len()) {
        let matched = PATTERN
            .iter()
            .enumerate()
            .all(|(i, byte)| byte.is_none_or(|b| text_bytes[off + i] == b));
        if !matched {
            continue;
        }

        let disp_load =
            i32::from_le_bytes(text_bytes[off + 3..off + 7].try_into().unwrap()) as isize;
        let disp_lea =
            i32::from_le_bytes(text_bytes[off + 20..off + 24].try_into().unwrap()) as isize;
        let head_va_from_load = ((text_va + off + 7) as isize + disp_load) as usize;
        let head_va_from_lea = ((text_va + off + 24) as isize + disp_lea) as usize;

        if head_va_from_load != head_va_from_lea {
            continue;
        }

        if match_va.is_some() {
            anyhow::bail!("ntdll PebLdr signature matched multiple locations");
        }

        match_va = Some(head_va_from_load - 0x10);
    }

    match_va.ok_or_else(|| anyhow!("failed to locate ntdll!PebLdr"))
}

/// Load only ntdll.dll from VFS for the ntdll-driven init approach.
///
/// Finds ntdll.dll in the VFS, rewrites its syscall stubs to use the
/// trampoline, and loads it into guest memory via `mapper`.
pub fn load_ntdll_for_init(
    fs: &litebox_shim_windows::NtFS,
    mapper: &mut PmMapper<'_>,
    partition_start: usize,
) -> Result<NtdllInitLoadResult> {
    let ntdll_path = find_vfs_file_by_name(fs, "ntdll.dll")
        .ok_or_else(|| anyhow!("ntdll.dll not found in VFS"))?;
    let ntdll_data = read_vfs_file(fs, &ntdll_path)?;
    trace_debugln!(
        "[real-dlls] Read ntdll.dll from VFS ({} bytes, path={ntdll_path:?})",
        ntdll_data.len()
    );
    let ntdll_load_va = partition_start + REAL_DLL_OFFSET;

    let trampoline_va = partition_start + TRAMPOLINE_OFFSET;

    // Instrument LdrpInitializeProcess error paths with INT3 breakpoints.
    // Temporarily disabled — uncomment the patching loop to re-enable.
    let error_path_rvas: &[usize] = &[
        // 0xBC053, // path 1: RtlImageNtHeaderEx failed
        // 0xBC202, // path 2: IFEO/mitigation failed
        // 0xBC2B7, // path 3: 0x10A500 EXE validation failed
        // 0xBC400, // path 4: 0xF8360 heap/loader setup failed
        // 0xBC611, // path 5: 0x66C30 failed
        // 0xBC631, // path 6: 0x119378 failed
    ];

    // Rewrite ntdll syscall stubs.
    let rewrite =
        ntdll_rewriter::rewrite_ntdll(&ntdll_data, ntdll_load_va as u64, trampoline_va as u64);
    trace_debugln!(
        "[real-dlls] Rewrote {} ntdll syscall stubs ({} identified), {} __fastfail patched",
        rewrite.stubs_rewritten,
        rewrite.stubs_identified,
        rewrite.fastfail_patched
    );
    // Log unhandled stubs for debugging.
    #[cfg(all(debug_assertions, feature = "trace_debug"))]
    for (nr, name) in &rewrite.unhandled_stubs {
        trace_debugln!("[real-dlls] unhandled stub: nr=0x{nr:04X} name={name}");
    }

    // -----------------------------------------------------------------------
    // Binary patching of ntdll internals.
    //
    // ntdll.dll is a kernel-owned binary that assumes it runs inside a real
    // Windows process managed by the kernel.  In our sandbox there is no
    // kernel, no CSRSS, no real scheduling, and the host's
    // KUSER_SHARED_DATA (KUSD) at 0x7FFE_0000 reports the host machine's
    // topology (e.g. 16 CPUs) rather than the sandbox's virtualised one.
    //
    // We apply a series of targeted binary patches to the raw PE image
    // bytes *before* loading them into guest memory.  This avoids the need
    // for a full kernel shim for each affected code path.
    //
    //  Patch                        Why
    //  ─────────────────────────────────────────────────────────────────
    //  CsrClient* → return 0       No CSRSS server; calls would hang.
    //  RtlGetCurrentProcessorNum-   Real impl uses rdtscp/rdpid which
    //    berEx → return {0,0}       reads the host CPU id.
    //  rdtscp → xor ecx,ecx; nop   Same reason; ECX (IA32_TSC_AUX)
    //                               must always be 0 (= CPU 0).
    //  KUSD disp32 0x7FFE → 0x7FFD Redirect reads of the kernel-mapped
    //                               shared data page to a shadow copy
    //                               where we control field values
    //                               (ActiveProcessorCount = 1, etc.).
    //
    // Patches are additive: if ntdll is updated and a pattern no longer
    // matches, we log a warning but continue — nothing crashes silently.
    // -----------------------------------------------------------------------
    let mut image = rewrite.image;
    {
        // Find .text section to compute file offset from RVA
        let parsed_tmp = PeParsedFile::parse(&image)
            .map_err(|e| anyhow!("Failed to parse for patching: {e}"))?;
        for &rva in error_path_rvas {
            if let Some(file_off) = parsed_tmp.rva_to_file_offset(rva as u32) {
                image[file_off] = 0xCC; // INT3
                trace_debugln!("[real-dlls] INT3 at ntdll+0x{rva:X} (file offset 0x{file_off:X})");
            } else {
                trace_debugln!("[real-dlls] WARN: could not patch INT3 at ntdll+0x{rva:X}");
            }
        }

        // --- Patch 1: CSRSS client stubs ─────────────────────────────────
        //
        // CsrClientConnectToServer and CsrClientCallServer try to talk to the
        // Win32 subsystem server (csrss.exe) via LPC/ALPC.  There is no CSRSS
        // in the sandbox, so these calls would deadlock.
        //
        // CsrClientConnectToServer is converted into a pseudo-syscall
        // (trampolined to the shim) so that the shim can fill in the
        // ConnectionInformation output buffer.  Without this, USER32's
        // _UserClientDllInitialize copies an empty buffer into gSharedInfo,
        // leaving gSharedInfo.psi = NULL and causing DllMain to fail.
        //
        // CsrClientCallServer (fire-and-forget) keeps the simple
        // `xor eax, eax; ret` (STATUS_SUCCESS) patch.
        let trampoline_code_va = (trampoline_va as u64) + 0x18;

        // Patch CsrClientConnectToServer → pseudo-syscall trampoline.
        {
            let rva_opt = {
                let exports = parsed_tmp.exports(&image);
                exports
                    .iter()
                    .find(|e| e.name == Some("CsrClientConnectToServer"))
                    .map(|e| e.rva)
            };
            if let Some(rva) = rva_opt {
                if let Some(off) = parsed_tmp.rva_to_file_offset(rva) {
                    // 22-byte stub: mov r10,rcx; mov eax,NR; jmp [rip+0]; <8-byte addr>
                    if off + 22 <= image.len() {
                        let nr = litebox_common_windows::stub_dlls::CSR_CLIENT_CONNECT_TO_SERVER;
                        image[off] = 0x4C; // mov r10, rcx
                        image[off + 1] = 0x8B;
                        image[off + 2] = 0xD1;
                        image[off + 3] = 0xB8; // mov eax, <nr>
                        image[off + 4..off + 8].copy_from_slice(&nr.to_le_bytes());
                        image[off + 8] = 0xFF; // jmp [rip+0]
                        image[off + 9] = 0x25;
                        image[off + 10..off + 14].copy_from_slice(&0u32.to_le_bytes());
                        image[off + 14..off + 22]
                            .copy_from_slice(&trampoline_code_va.to_le_bytes());
                        trace_debugln!(
                            "[real-dlls] Patched CsrClientConnectToServer → pseudo-syscall 0x{nr:X} at ntdll+0x{rva:X}"
                        );
                    }
                }
            } else {
                trace_debugln!(
                    "[real-dlls] WARN: CsrClientConnectToServer not found in ntdll exports"
                );
            }
        }

        // Patch CsrClientCallServer → xor eax, eax; ret (STATUS_SUCCESS).
        {
            let rva_opt = {
                let exports = parsed_tmp.exports(&image);
                exports
                    .iter()
                    .find(|e| e.name == Some("CsrClientCallServer"))
                    .map(|e| e.rva)
            };
            if let Some(rva) = rva_opt {
                if let Some(off) = parsed_tmp.rva_to_file_offset(rva)
                    && off + 3 <= image.len()
                {
                    image[off] = 0x31; // xor eax, eax
                    image[off + 1] = 0xC0;
                    image[off + 2] = 0xC3; // ret
                    trace_debugln!("[real-dlls] Patched CsrClientCallServer at ntdll+0x{rva:X}");
                }
            } else {
                trace_debugln!("[real-dlls] WARN: CsrClientCallServer not found in ntdll exports");
            }
        }

        // --- Patch 2: RtlGetCurrentProcessorNumberEx → always CPU 0 --------
        //
        // The real implementation reads the host CPU number from the
        // IA32_TSC_AUX MSR via `rdtscp` (or `rdpid`).  In the sandbox every
        // thread must appear to run on virtual CPU 0 so that ntdll's segment
        // heap, NUMA-aware allocator, and other per-processor structures all
        // index into arena 0 (the only one that gets fully initialised in a
        // single-CPU environment).
        //
        // Replacement: xor eax, eax ; mov [rcx], eax ; ret  (31 C0 89 01 C3)
        // The function's signature is void(PPROCESSOR_NUMBER), so zeroing
        // *rcx sets both Group and Number to 0.
        {
            let rva_opt = {
                let exports = parsed_tmp.exports(&image);
                exports
                    .iter()
                    .find(|e| e.name == Some("RtlGetCurrentProcessorNumberEx"))
                    .map(|e| e.rva)
            };
            if let Some(rva) = rva_opt {
                if let Some(off) = parsed_tmp.rva_to_file_offset(rva)
                    && off + 5 <= image.len()
                {
                    image[off] = 0x31; // xor eax, eax
                    image[off + 1] = 0xC0;
                    image[off + 2] = 0x89; // mov [rcx], eax
                    image[off + 3] = 0x01;
                    image[off + 4] = 0xC3; // ret
                    trace_debugln!(
                        "[real-dlls] Patched RtlGetCurrentProcessorNumberEx at ntdll+0x{rva:X}"
                    );
                }
            } else {
                trace_debugln!(
                    "[real-dlls] WARN: RtlGetCurrentProcessorNumberEx not found in ntdll exports"
                );
            }
        }

        // --- Patch 3: rdtscp → xor ecx, ecx; nop  -------------------------
        //
        // `rdtscp` (0F 01 F9) writes the IA32_TSC_AUX value (host CPU id)
        // into ECX alongside the timestamp in EDX:EAX.  ntdll uses the ECX
        // result to choose per-processor data structures.  We replace every
        // occurrence with `xor ecx, ecx; nop` (31 C9 90), which preserves
        // the 3-byte instruction length and forces ECX = 0 (CPU 0).
        //
        // The timestamp in EDX:EAX is lost, but performance timing in the
        // sandbox goes through NtQueryPerformanceCounter instead.
        {
            let text_section = parsed_tmp
                .sections
                .iter()
                .find(|s| s.name.starts_with(b".text"));
            let rdtscp_pattern: [u8; 3] = [0x0F, 0x01, 0xF9];
            let replacement: [u8; 3] = [0x31, 0xC9, 0x90]; // xor ecx, ecx; nop
            let mut count = 0u32;
            if let Some(ts) = text_section {
                let start = ts.pointer_to_raw_data as usize;
                let end = (start + ts.size_of_raw_data as usize).min(image.len());
                let text = &mut image[start..end];
                let mut pos = 0usize;
                while pos + 3 <= text.len() {
                    if text[pos..pos + 3] == rdtscp_pattern {
                        text[pos..pos + 3].copy_from_slice(&replacement);
                        count += 1;
                    }
                    pos += 1;
                }
            }
            if count > 0 {
                trace_debugln!(
                    "[real-dlls] Replaced {count} rdtscp instructions with xor ecx, ecx"
                );
            }
        }

        // --- Patch 4: KUSD shadow page (0x7FFE → 0x7FFD) ------------------
        //
        // KUSER_SHARED_DATA (KUSD) at 0x7FFE_0000 is a read-only page the
        // kernel maps into every process.  It exposes system-wide state:
        // tick counts, OS version, QPC frequency, and — critically — the
        // host's ActiveProcessorCount (offset 0x3C0).
        //
        // ntdll's segment heap reads ActiveProcessorCount during
        // RtlCreateHeap to size per-processor arena arrays.  If the guest
        // sees the host's real count (e.g. 16) it allocates 16 arena slots
        // but only initialises the ones actually touched.  Later, when a
        // heap allocation hashes to an uninitialised slot, the null arena
        // pointer causes an access violation in RtlAllocateHeap.
        //
        // We cannot VirtualProtect the real KUSD (it's kernel-owned), so
        // we allocate a shadow copy at 0x7FFD_0000 with the fields we need
        // to override (ActiveProcessorCount = 1, etc.) and then rewrite
        // ntdll's absolute `[disp32]` memory operands to read from the
        // shadow instead.
        //
        // x86-64 SIB encoding for [disp32]: the ModR/M byte has MOD=00
        // and R/M=100 (SIB follows), then SIB=0x25 (SS=00, Index=none,
        // Base=disp32), then the 4-byte little-endian displacement.  We
        // match this 6-byte sequence and change the 0xFE byte to 0xFD.
        {
            let shadow = create_kusd_shadow();
            if shadow != 0 {
                // Scan the ENTIRE image for the exact 4-byte displacement
                // of each known KUSD offset. The displacement bytes for
                // 0x7FFE_0xxx are [lo, hi, 0xFE, 0x7F]. We change the
                // 0xFE byte to 0xFD, redirecting to 0x7FFD_0xxx.
                //
                // Known KUSD offsets accessed by ntdll (from disassembly):
                let kusd_offsets: &[u16] = &[
                    0x004, // TickCountMultiplier
                    0x297, // NtGlobalFlag2 or similar
                    0x2D6, // processor feature flag
                    0x330, // cookie / security
                    0x36A, // processor group info
                    0x3C0, // ActiveProcessorCount ← critical for heap
                    0x3EC, // SharedDataFlags
                    0x708, // QPC-related
                ];

                let text_section = parsed_tmp
                    .sections
                    .iter()
                    .find(|s| s.name.starts_with(b".text"));
                #[cfg(all(debug_assertions, feature = "trace_debug"))]
                let mut kusd_patch_count = 0u32;
                if let Some(ts) = text_section {
                    let file_start = ts.pointer_to_raw_data as usize;
                    // Use size_of_raw_data (file-backed bytes), not virtual_size
                    // which may extend past file data into the next section.
                    let file_end = (file_start + ts.size_of_raw_data as usize).min(image.len());
                    let text_bytes = &mut image[file_start..file_end];

                    for &off in kusd_offsets {
                        // Build the 4-byte displacement for 0x7FFE_0xxx.
                        let disp: [u8; 4] =
                            [(off & 0xFF) as u8, ((off >> 8) & 0xFF) as u8, 0xFE, 0x7F];

                        // Scan for [ModR/M] [SIB=0x25] [disp32] in the text.
                        // The SIB byte 0x25 = (SS=00, Index=100/none, Base=101/disp32).
                        // The ModR/M byte must have MOD=00 and R/M=100 (SIB follow),
                        // i.e., (byte & 0xC7) == 0x04. This 2-byte prefix excludes
                        // false positives where 0x25 is the AND opcode or part of an
                        // unrelated immediate.
                        let mut pos = 1usize; // start at 1 to allow pos-1 check
                        while pos + 5 <= text_bytes.len() {
                            if text_bytes[pos] == 0x25
                                && text_bytes[pos + 1..pos + 5] == disp
                                && (text_bytes[pos - 1] & 0xC7) == 0x04
                            {
                                // Replace FE → FD at the 0xFE byte position.
                                text_bytes[pos + 3] = 0xFD;
                                #[cfg(all(debug_assertions, feature = "trace_debug"))]
                                {
                                    kusd_patch_count += 1;
                                }
                                pos += 5; // skip past this match
                            } else {
                                pos += 1;
                            }
                        }
                    }
                }
                #[cfg(all(debug_assertions, feature = "trace_debug"))]
                trace_debugln!(
                    "[real-dlls] KUSD shadow at 0x{shadow:X}, patched {kusd_patch_count} \
                     ntdll references"
                );
            } else {
                trace_debugln!(
                    "[real-dlls] WARN: failed to allocate KUSD shadow page at 0x7FFD0000"
                );
            }
        }

        // --- Patch 5: Inverted function table empty-table crash guard --------
        //
        // DISABLED: Now that we populate the inverted function table for all
        // loaded DLLs (both from the runner and the shim's NtMapViewOfSection),
        // this patch is no longer needed.  The original code at RVA 0x101FC
        // (`mov rax,[rdi]; cmp rbx,rax`) should work correctly with a
        // populated table.  Leaving the patch in place causes the error path
        // to return STATUS_BAD_STACK (0xC0000028), which breaks SEH unwinding
        // in the rare case where the table iterator hits an edge condition.
        //
        // Original patch: jmp +0x201 → 0x10402 (STATUS_BAD_STACK return)
        // Now: no-op (table is populated, so the code should work as-is).
        // (patching code removed)
    }

    // Parse and load ntdll into guest memory.
    let parsed =
        PeParsedFile::parse(&image).map_err(|e| anyhow!("Failed to parse rewritten ntdll: {e}"))?;
    let image_size = parsed.size_of_image as usize;
    mapper
        .pre_reserve(ntdll_load_va, image_size)
        .map_err(|e| anyhow!("Failed to reserve VA for ntdll: {e:?}"))?;
    let info = load_pe(&parsed, &image, ntdll_load_va, mapper)
        .map_err(|e| anyhow!("Failed to load ntdll: {e}"))?;

    trace_debugln!(
        "[real-dlls] ntdll loaded at 0x{:X} (size=0x{:X})",
        info.image_base,
        info.image_size
    );

    let ldrp_hash_table_va = find_ntdll_hash_table_va(&parsed, info.image_base)?;
    trace_debugln!("[real-dlls] LdrpHashTable at 0x{ldrp_hash_table_va:X}");

    let pebldr_va = find_ntdll_pebldr_va(&parsed, info.image_base)?;
    trace_debugln!("[real-dlls] PebLdr at 0x{pebldr_va:X}");

    // Make ntdll's .mrdata section writable.  This section contains internal
    // mutable data (KiUserInvertedFunctionTable, loader data, etc.) that
    // ntdll's code needs to write during initialization.  On real Windows the
    // kernel loads ntdll with writable .mrdata; our load_pe uses the PE section
    // flags which may mark it read-only.
    for section in &parsed.sections {
        let name = core::str::from_utf8(&section.name)
            .unwrap_or("")
            .trim_end_matches('\0');
        if name == ".mrdata" {
            let start = info.image_base + section.virtual_address as usize;
            let vsize = section.virtual_size.max(section.size_of_raw_data) as usize;
            let pages = (vsize + 0xFFF) & !0xFFF;
            unsafe {
                for off in (0..pages).step_by(0x1000) {
                    let addr = start + off;
                    let ptr = addr as *mut u8;
                    // Make writable via the host OS.
                    let mut old_protect: u32 = 0;
                    unsafe extern "system" {
                        fn VirtualProtect(
                            addr: *mut u8,
                            size: usize,
                            new_protect: u32,
                            old_protect: *mut u32,
                        ) -> i32;
                    }
                    VirtualProtect(
                        ptr,
                        0x1000,
                        0x04, /* PAGE_READWRITE */
                        &raw mut old_protect,
                    );
                }
            }
            trace_debugln!(
                "[real-dlls] Made .mrdata writable: 0x{start:X}..0x{:X} ({pages} bytes)",
                start + pages
            );
        }
    }

    // Find LdrInitializeThunk and RtlUserThreadStart exports.
    let exports = parsed.exports(&image);
    #[allow(clippy::similar_names)]
    let (ldr_init_thunk_va, rtl_user_thread_start_va) = {
        let ldr_init_rva = exports
            .iter()
            .find(|e| e.name == Some("LdrInitializeThunk"))
            .map(|e| e.rva)
            .ok_or_else(|| anyhow!("ntdll missing LdrInitializeThunk export"))?;
        let rtl_user_thread_start_rva = exports
            .iter()
            .find(|e| e.name == Some("RtlUserThreadStart"))
            .map(|e| e.rva)
            .ok_or_else(|| anyhow!("ntdll missing RtlUserThreadStart export"))?;

        (
            ntdll_load_va + ldr_init_rva as usize,
            ntdll_load_va + rtl_user_thread_start_rva as usize,
        )
    };

    trace_debugln!(
        "[real-dlls] LdrInitializeThunk at 0x{ldr_init_thunk_va:X}, \
         RtlUserThreadStart at 0x{rtl_user_thread_start_va:X}"
    );

    // Also look up KiUserExceptionDispatcher for SEH dispatch.
    let ki_user_exception_dispatcher_rva = exports
        .iter()
        .find(|e| e.name == Some("KiUserExceptionDispatcher"))
        .map(|e| e.rva as usize);

    // --- Populate the inverted function table for ntdll -----------------------
    //
    // On real Windows the kernel writes ntdll's RUNTIME_FUNCTION table into
    // `KiUserInvertedFunctionTable` before giving control to user mode.  Our
    // guest ntdll's copy is initialised from the PE file where entry 0 is all
    // zeroes.  Without it, RtlDispatchException can't walk the SEH chain and
    // any exception during init becomes unhandleable (infinite NtRaiseException
    // loop).
    //
    // KiUserInvertedFunctionTable layout:
    //   +0x00  u32  CurrentSize (already 1 in the PE)
    //   +0x04  u32  MaximumSize (512)
    //   +0x08  u32  Epoch
    //   +0x0C  u8   Overflow + 3 reserved
    //   +0x10  Entry[0]:
    //     +0x00  u64  ExceptionDirectory   (ptr to RUNTIME_FUNCTION array)
    //     +0x08  u64  ImageBase
    //     +0x10  u32  ImageSize
    //     +0x14  u32  ExceptionDirectorySize
    let mut ift_va_result = 0usize;
    if let Some(ift_export) = exports
        .iter()
        .find(|e| e.name == Some("KiUserInvertedFunctionTable"))
    {
        let ift_va = ntdll_load_va + ift_export.rva as usize;
        ift_va_result = ift_va;
        // Exception directory (.pdata) from the PE data directories.
        if parsed.data_directories.len() > IMAGE_DIRECTORY_ENTRY_EXCEPTION {
            let exc_dir = &parsed.data_directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if exc_dir.virtual_address != 0 && exc_dir.size != 0 {
                let entry_va = ift_va + 0x10; // first table entry
                let exc_dir_va = ntdll_load_va + exc_dir.virtual_address as usize;

                // Safety: ift_va points into committed guest memory (ntdll's
                // .mrdata section) that we just loaded.
                unsafe {
                    // Entry.ExceptionDirectory (u64)
                    (entry_va as *mut u64).write(exc_dir_va as u64);
                    // Entry.ImageBase (u64)
                    ((entry_va + 8) as *mut u64).write(ntdll_load_va as u64);
                    // Entry.ImageSize (u32)
                    ((entry_va + 16) as *mut u32).write(parsed.size_of_image);
                    // Entry.ExceptionDirectorySize (u32)
                    ((entry_va + 20) as *mut u32).write(exc_dir.size);
                }

                trace_debugln!(
                    "[real-dlls] Populated KiUserInvertedFunctionTable entry 0: \
                     ExcDir=0x{exc_dir_va:X} Base=0x{ntdll_load_va:X} \
                     Size=0x{:X} ExcSize=0x{:X}",
                    parsed.size_of_image,
                    exc_dir.size
                );
            }
        }
    } else {
        trace_debugln!("[real-dlls] WARN: KiUserInvertedFunctionTable export not found");
    }

    let ntdll = LoadedDll {
        name: String::from("ntdll.dll"),
        base_address: info.image_base,
        image_size: info.image_size,
        entry_point: if parsed.entry_point != 0 {
            info.image_base + parsed.entry_point as usize
        } else {
            0
        },
        pe_data: image,
        has_entry_point: parsed.entry_point != 0,
    };

    Ok(NtdllInitLoadResult {
        ntdll,
        trampoline: rewrite.trampoline,
        trampoline_va,
        entry_ptr_offset: rewrite.entry_ptr_offset,
        gs_table_ptr_offset: rewrite.gs_table_ptr_offset,
        reverse_gs_table_ptr_offset: rewrite.reverse_gs_table_ptr_offset,
        stubs_rewritten: rewrite.stubs_rewritten,
        stubs_identified: rewrite.stubs_identified,
        ldr_init_thunk_va,
        rtl_user_thread_start_va,
        syscall_map: rewrite.syscall_map,
        unhandled_stubs: rewrite.unhandled_stubs,
        ki_user_exception_dispatcher_rva,
        inverted_function_table_va: ift_va_result,
        ldrp_hash_table_va,
        pebldr_va,
    })
}

/// Result of loading all real DLLs.
#[allow(dead_code)]
pub struct RealDllLoadResult {
    /// All loaded DLLs.
    pub dlls: Vec<LoadedDll>,
    /// The trampoline page bytes (must be mapped at `trampoline_va`).
    pub trampoline: Vec<u8>,
    /// VA where the trampoline should be mapped.
    pub trampoline_va: usize,
    /// Offset within trampoline where the shim entry pointer goes.
    pub entry_ptr_offset: usize,
    /// Offset within trampoline where the forward GS table pointer goes.
    pub gs_table_ptr_offset: usize,
    /// Offset within trampoline where the reverse GS table pointer goes.
    pub reverse_gs_table_ptr_offset: usize,
    /// Number of ntdll syscall stubs that were rewritten.
    pub stubs_rewritten: usize,
    /// Number of stubs whose syscall number was identified.
    pub stubs_identified: usize,
    /// IAT patches to apply to guest memory (EXE + all inter-DLL).
    pub iat_patches: Vec<IatPatch>,
    /// Imports that couldn't be resolved (patched with fallback).
    pub unresolved_imports: Vec<String>,
}

/// Offset from partition start for loading real DLLs. Each DLL is spaced
/// 64MB apart to avoid overlap (the largest DLL, shell32.dll, is ~8MB).
/// Placed at ~508 GiB to leave room above for MEM_TOP_DOWN heap
/// reservations within the 1 TiB guest VA partition.
pub const REAL_DLL_OFFSET: usize = 0x7F_0000_0000;
#[allow(dead_code)]
const DLL_SPACING: usize = 0x0400_0000; // 64MB

/// Offset for the ntdll syscall trampoline relative to partition start.
/// Placed just below the DLL region to avoid 64KB alignment conflicts.
const TRAMPOLINE_OFFSET: usize = REAL_DLL_OFFSET - 0x1_0000;

// ── Tar reader ──────────────────────────────────────────────────────

// ── DLL loader ──────────────────────────────────────────────────────

/// Load real DLLs from a pre-extracted tar file map.
///
/// `tar_files` is the result of `read_tar()` — a map of lowercased
/// filenames to their PE bytes. It must contain `ntdll.dll` and all
/// other DLLs needed by the main EXE.
///
/// `exe_parsed`, `exe_data`, and `exe_base` describe the already-loaded
/// main executable. Imports are resolved for both the EXE and all DLLs.
///
/// `fallback_va` is written into IAT slots for unresolved imports
/// (should point to a stub that logs and returns 0).
#[allow(dead_code, clippy::items_after_statements)]
pub fn load_real_dlls(
    tar_files: &BTreeMap<String, Vec<u8>>,
    exe_parsed: &PeParsedFile,
    exe_data: &[u8],
    exe_base: usize,
    mapper: &mut PmMapper<'_>,
    fallback_va: u64,
    partition_start: usize,
) -> Result<RealDllLoadResult> {
    // Separate DLLs from non-DLL entries (e.g., node.exe).
    let mut dll_files: BTreeMap<String, &[u8]> = BTreeMap::new();
    for (name, data) in tar_files {
        if name
            .get(name.len().saturating_sub(4)..)
            .is_some_and(|ext| ext.eq_ignore_ascii_case(".dll"))
        {
            dll_files.insert(name.clone(), data.as_slice());
        }
    }

    trace_debugln!("[real-dlls] {} DLLs in tar", dll_files.len());

    // Step 1: Rewrite ntdll.dll syscalls.
    // ntdll always gets load slot 0.
    let ntdll_load_va = partition_start + REAL_DLL_OFFSET;
    let trampoline_va = partition_start + TRAMPOLINE_OFFSET;
    let rewrite = if let Some(ntdll_data) = dll_files.get("ntdll.dll") {
        let result =
            ntdll_rewriter::rewrite_ntdll(ntdll_data, ntdll_load_va as u64, trampoline_va as u64);
        trace_debugln!(
            "[real-dlls] Rewrote {} ntdll syscall stubs ({} identified), {} __fastfail patched",
            result.stubs_rewritten,
            result.stubs_identified,
            result.fastfail_patched
        );
        result
    } else {
        return Err(anyhow!("ntdll.dll not found in tar"));
    };

    // Step 2: Determine load order.
    // Priority DLLs first (ntdll → kernelbase → kernel32), then alphabetical.
    let mut load_order: Vec<String> = Vec::new();
    for p in ["ntdll.dll", "kernelbase.dll", "kernel32.dll"] {
        if dll_files.contains_key(p) {
            load_order.push(p.to_string());
        }
    }
    for name in dll_files.keys() {
        if !load_order.contains(name) {
            load_order.push(name.clone());
        }
    }

    // Step 3: Load each DLL into guest memory.
    // We keep owned copies of PE data alongside the loaded info so that
    // we can resolve imports later.
    struct DllEntry {
        name: String,
        base: usize,
        size: usize,
        entry: usize,
        has_ep: bool,
        data: Vec<u8>,
        parsed: PeParsedFile,
    }

    let mut entries: Vec<DllEntry> = Vec::with_capacity(load_order.len());

    for (slot, name) in load_order.iter().enumerate() {
        let load_va = partition_start + REAL_DLL_OFFSET + slot * DLL_SPACING;

        // For ntdll, use the rewritten image.
        let pe_data: &[u8] = if name == "ntdll.dll" {
            &rewrite.image
        } else {
            dll_files[name.as_str()]
        };

        let parsed =
            PeParsedFile::parse(pe_data).map_err(|e| anyhow!("Failed to parse {name}: {e}"))?;

        // Pre-reserve the entire image so per-section MEM_COMMIT works.
        let image_size = parsed.size_of_image as usize;
        mapper
            .pre_reserve(load_va, image_size)
            .map_err(|e| anyhow!("Failed to reserve VA for {name}: {e:?}"))?;

        let info = load_pe(&parsed, pe_data, load_va, mapper)
            .map_err(|e| anyhow!("Failed to load {name}: {e}"))?;

        let has_ep = parsed.entry_point != 0;
        let entry_point = if has_ep {
            info.image_base + parsed.entry_point as usize
        } else {
            0
        };

        trace_debugln!(
            "[real-dlls] Loaded {name} at 0x{:X} (size=0x{:X}{})",
            info.image_base,
            info.image_size,
            if has_ep {
                format!(", ep=0x{entry_point:X}")
            } else {
                String::new()
            }
        );

        entries.push(DllEntry {
            name: name.clone(),
            base: info.image_base,
            size: info.image_size,
            entry: entry_point,
            has_ep,
            data: pe_data.to_vec(),
            parsed,
        });
    }

    // Step 4: Resolve imports.
    // Build the module list referencing our entries.
    let modules: Vec<LoadedModule<'_>> = entries
        .iter()
        .map(|e| LoadedModule {
            name: &e.name,
            base_address: e.base,
            pe_data: &e.data,
            parsed: &e.parsed,
        })
        .collect();

    let mut all_patches: Vec<IatPatch> = Vec::new();
    let mut all_unresolved: Vec<String> = Vec::new();

    // Resolve EXE imports against the loaded DLLs.
    let (patches, unresolved) = litebox_common_windows::pe_loader::resolve_imports_lenient(
        exe_parsed,
        exe_data,
        exe_base,
        &modules,
        fallback_va,
    )
    .map_err(|e| anyhow!("Failed to resolve EXE imports: {e}"))?;
    all_patches.extend(patches);
    all_unresolved.extend(unresolved);

    // Resolve inter-DLL imports.
    for entry in &entries {
        let (patches, unresolved) = litebox_common_windows::pe_loader::resolve_imports_lenient(
            &entry.parsed,
            &entry.data,
            entry.base,
            &modules,
            fallback_va,
        )
        .map_err(|e| anyhow!("Failed to resolve {} imports: {e}", entry.name))?;
        all_patches.extend(patches);
        all_unresolved.extend(unresolved);
    }

    if !all_unresolved.is_empty() {
        trace_debugln!(
            "[real-dlls] {} unresolved imports (fallback stub):",
            all_unresolved.len()
        );
        #[cfg(all(debug_assertions, feature = "trace_debug"))]
        for (i, name) in all_unresolved.iter().enumerate() {
            if i >= 30 {
                trace_debugln!("  ... and {} more", all_unresolved.len() - 30);
                break;
            }
            trace_debugln!("  {name}");
        }
    }

    // Patch problematic ntdll internal functions that crash without full
    // LdrpInitialize. Replace their entry points with `mov eax, <status>; ret`.
    let ntdll_entry = entries
        .iter()
        .find(|e| e.name.eq_ignore_ascii_case("ntdll.dll"));
    if let Some(ntdll) = ntdll_entry {
        let ntdll_exports = ntdll.parsed.exports(&ntdll.data);
        // Functions to stub out with error-return codes.
        let stubs: &[(&str, u32)] = &[
            // SxS activation context: returns STATUS_SXS_KEY_NOT_FOUND
            ("RtlFindActivationContextSectionString", 0xC015_0008),
            ("RtlActivateActivationContextUnsafeFast", 0),
            ("RtlDeactivateActivationContextUnsafeFast", 0),
            // Loader notifications: no-op
            ("LdrRegisterDllNotification", 0xC000_0002), // STATUS_NOT_IMPLEMENTED
        ];
        for (name, status) in stubs {
            if let Some(exp) = ntdll_exports.iter().find(|e| e.name == Some(name)) {
                let va = ntdll.base + exp.rva as usize;
                // Write: mov eax, <status>; ret (6 bytes)
                let patch: [u8; 6] = [
                    0xB8,
                    (*status & 0xFF) as u8,
                    ((*status >> 8) & 0xFF) as u8,
                    ((*status >> 16) & 0xFF) as u8,
                    ((*status >> 24) & 0xFF) as u8,
                    0xC3,
                ];
                unsafe {
                    // Make writable via PM, patch, restore to executable.
                    use litebox::platform::{RawConstPointer as _, RawPointerProvider};
                    let ptr = <crate::Platform as RawPointerProvider>::RawMutPointer::from_usize(
                        va & !(crate::PAGE_SIZE - 1),
                    );
                    let _ = mapper.pm.make_pages_writable(ptr, crate::PAGE_SIZE);
                    core::ptr::copy_nonoverlapping(patch.as_ptr(), va as *mut u8, 6);
                    let _ = mapper.pm.make_pages_executable(ptr, crate::PAGE_SIZE);
                }
                trace_debugln!("[real-dlls] Patched {name} at 0x{va:X} -> ret 0x{status:08X}");
            }
        }
    }

    // Build the result.
    let loaded_dlls = entries
        .into_iter()
        .map(|e| LoadedDll {
            name: e.name,
            base_address: e.base,
            image_size: e.size,
            entry_point: e.entry,
            pe_data: e.data,
            has_entry_point: e.has_ep,
        })
        .collect();

    Ok(RealDllLoadResult {
        dlls: loaded_dlls,
        trampoline: rewrite.trampoline,
        trampoline_va,
        entry_ptr_offset: rewrite.entry_ptr_offset,
        gs_table_ptr_offset: rewrite.gs_table_ptr_offset,
        reverse_gs_table_ptr_offset: rewrite.reverse_gs_table_ptr_offset,
        stubs_rewritten: rewrite.stubs_rewritten,
        stubs_identified: rewrite.stubs_identified,
        iat_patches: all_patches,
        unresolved_imports: all_unresolved,
    })
}

// ---------------------------------------------------------------------------
// KUSER_SHARED_DATA shadow
// ---------------------------------------------------------------------------

/// Offset of `ActiveProcessorCount` within KUSER_SHARED_DATA.
const KUSD_ACTIVE_PROCESSOR_COUNT_OFFSET: usize = 0x3C0;

/// Base address of the real KUSER_SHARED_DATA page.
const KUSD_REAL_BASE: usize = 0x7FFE_0000;

/// Target address for our shadow page (one 64KB block below real KUSD).
const KUSD_SHADOW_BASE: usize = 0x7FFD_0000;

/// Allocate a shadow KUSER_SHARED_DATA page at [`KUSD_SHADOW_BASE`],
/// copy the host's real KUSD into it, and set `ActiveProcessorCount` to 1.
///
/// Returns the shadow base address on success, or 0 on failure.
fn create_kusd_shadow() -> usize {
    unsafe extern "system" {
        fn VirtualAlloc(addr: usize, size: usize, alloc_type: u32, protect: u32) -> usize;
    }

    const MEM_COMMIT_RESERVE: u32 = 0x1000 | 0x2000; // MEM_COMMIT | MEM_RESERVE
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_SIZE: usize = 0x1000;

    // Try to allocate at the preferred shadow address.
    let alloc = unsafe {
        VirtualAlloc(
            KUSD_SHADOW_BASE,
            PAGE_SIZE,
            MEM_COMMIT_RESERVE,
            PAGE_READWRITE,
        )
    };
    if alloc == 0 {
        return 0;
    }
    assert_eq!(alloc, KUSD_SHADOW_BASE);

    // Copy the real KUSD page to the shadow.
    unsafe {
        core::ptr::copy_nonoverlapping(KUSD_REAL_BASE as *const u8, alloc as *mut u8, PAGE_SIZE);
    }

    // Override fields that must differ in the sandbox.
    unsafe {
        // ActiveProcessorCount → 4
        //
        // The NT segment heap (Windows 10+) creates per-context structures
        // indexed by a value derived from ActiveProcessorCount. With count=1,
        // only context 0's structure gets initialized (at cage_base+0x0),
        // but context 2 (backend, at cage_base+0xCC0) is still allocated and
        // used — leading to a crash on uninitialized data. Setting count >= 3
        // ensures all per-context structures are initialized.
        let apc_ptr = (alloc + KUSD_ACTIVE_PROCESSOR_COUNT_OFFSET) as *mut u32;
        core::ptr::write(apc_ptr, 4);
    }

    // Make the shadow read-only (mirrors the real KUSD's protection).
    unsafe extern "system" {
        fn VirtualProtect(
            addr: *mut u8,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
    }
    let mut old_prot: u32 = 0;
    unsafe {
        VirtualProtect(
            alloc as *mut u8,
            PAGE_SIZE,
            PAGE_READONLY,
            &raw mut old_prot,
        )
    };

    alloc
}
