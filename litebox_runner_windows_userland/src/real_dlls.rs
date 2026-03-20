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
use litebox_common_windows::pe_loader::{IatPatch, LoadedModule, load_pe};
use litebox_common_windows::pe_parser::PeParsedFile;

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
    /// Offset within trampoline where the GS table pointer goes.
    pub gs_table_ptr_offset: usize,
    /// Number of ntdll syscall stubs that were rewritten.
    pub stubs_rewritten: usize,
    /// Number of stubs whose syscall number was identified (matched export name).
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
}

/// Load only ntdll.dll from the tar for the ntdll-driven init approach.
///
/// The ntdll image is rewritten (syscall stubs patched to use the trampoline),
/// and its `LdrInitializeThunk` and `RtlUserThreadStart` exports are located.
/// The runner should start execution at `LdrInitializeThunk` with a CONTEXT
/// pointing to `RtlUserThreadStart` + the EXE entry point.
pub fn load_ntdll_for_init(
    tar_files: &BTreeMap<String, Vec<u8>>,
    mapper: &mut PmMapper<'_>,
    partition_start: usize,
) -> Result<NtdllInitLoadResult> {
    let ntdll_data = find_by_filename(tar_files, "ntdll.dll")
        .map(|(_, data)| data)
        .ok_or_else(|| anyhow!("ntdll.dll not found in tar"))?;

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
        ntdll_rewriter::rewrite_ntdll(ntdll_data, ntdll_load_va as u64, trampoline_va as u64);
    eprintln!(
        "[real-dlls] Rewrote {} ntdll syscall stubs ({} identified)",
        rewrite.stubs_rewritten, rewrite.stubs_identified
    );
    // Log unhandled stubs for debugging.
    for (nr, name) in &rewrite.unhandled_stubs {
        eprintln!("[real-dlls] unhandled stub: nr=0x{nr:04X} name={name}");
    }

    // Patch INT3 breakpoints into the image bytes before mapping.
    let mut image = rewrite.image;
    {
        // Find .text section to compute file offset from RVA
        let parsed_tmp = PeParsedFile::parse(&image)
            .map_err(|e| anyhow!("Failed to parse for INT3 patching: {e}"))?;
        for &rva in error_path_rvas {
            if let Some(file_off) = parsed_tmp.rva_to_file_offset(rva as u32) {
                image[file_off] = 0xCC; // INT3
                eprintln!("[real-dlls] INT3 at ntdll+0x{rva:X} (file offset 0x{file_off:X})");
            } else {
                eprintln!("[real-dlls] WARN: could not patch INT3 at ntdll+0x{rva:X}");
            }
        }

        // Patch CSR-related functions that try to connect to CSRSS. There is
        // no CSRSS in the sandbox. We patch them to return STATUS_SUCCESS.
        // Patch bytes: xor eax, eax ; ret  (31 C0 C3)
        let csr_functions: &[&str] = &["CsrClientConnectToServer", "CsrClientCallServer"];
        // Collect (name, rva) first to avoid borrow conflicts with image.
        let csr_rvas: Vec<(String, u32)> = {
            let exports = parsed_tmp.exports(&image);
            csr_functions
                .iter()
                .filter_map(|&func_name| {
                    exports
                        .iter()
                        .find(|e| e.name == Some(func_name))
                        .map(|e| (func_name.to_string(), e.rva))
                })
                .collect()
        };
        for (name, rva) in &csr_rvas {
            if let Some(file_off) = parsed_tmp.rva_to_file_offset(*rva) {
                let off = file_off;
                if off + 3 <= image.len() {
                    image[off] = 0x31; // xor eax, eax
                    image[off + 1] = 0xC0;
                    image[off + 2] = 0xC3; // ret
                    eprintln!("[real-dlls] Patched {name} at ntdll+0x{rva:X}");
                }
            }
        }
        for func_name in csr_functions {
            if !csr_rvas.iter().any(|(n, _)| n == func_name) {
                eprintln!("[real-dlls] WARN: {func_name} not found in ntdll exports");
            }
        }
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

    eprintln!(
        "[real-dlls] ntdll loaded at 0x{:X} (size=0x{:X})",
        info.image_base, info.image_size
    );

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

    eprintln!(
        "[real-dlls] LdrInitializeThunk at 0x{ldr_init_thunk_va:X}, \
         RtlUserThreadStart at 0x{rtl_user_thread_start_va:X}"
    );

    // Also look up KiUserExceptionDispatcher for SEH dispatch.
    let ki_user_exception_dispatcher_rva = exports
        .iter()
        .find(|e| e.name == Some("KiUserExceptionDispatcher"))
        .map(|e| e.rva as usize);

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
        stubs_rewritten: rewrite.stubs_rewritten,
        stubs_identified: rewrite.stubs_identified,
        ldr_init_thunk_va,
        rtl_user_thread_start_va,
        syscall_map: rewrite.syscall_map,
        unhandled_stubs: rewrite.unhandled_stubs,
        ki_user_exception_dispatcher_rva,
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
    /// Offset within trampoline where the GS table pointer goes.
    pub gs_table_ptr_offset: usize,
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

/// Extract all files from a ustar tar archive into a name→data map.
/// Names are lowercased. Ignores directory entries and non-regular files.
pub fn read_tar(tar_data: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pos = 0;
    while pos + 512 <= tar_data.len() {
        let header = &tar_data[pos..pos + 512];
        // End-of-archive: two consecutive zero blocks.
        if header.iter().all(|&b| b == 0) {
            break;
        }
        // Parse size from octal field at offset 124..136.
        let size_str = core::str::from_utf8(&header[124..136])
            .map_err(|_| anyhow!("invalid tar size field"))?
            .trim_end_matches('\0')
            .trim();
        let size = usize::from_str_radix(size_str, 8)
            .map_err(|_| anyhow!("invalid tar size: {size_str:?}"))?;
        // Parse name from offset 0..100, NUL-terminated.
        let name_end = header[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = core::str::from_utf8(&header[..name_end])
            .map_err(|_| anyhow!("invalid tar name"))?
            .to_lowercase();
        // Type flag at offset 156: '0' or '\0' = regular file.
        let typeflag = header[156];
        let data_start = pos + 512;
        let data_end = data_start + size;
        if data_end > tar_data.len() {
            return Err(anyhow!("tar entry {name} truncated"));
        }
        if (typeflag == b'0' || typeflag == 0) && size > 0 {
            files.insert(name, tar_data[data_start..data_end].to_vec());
        }
        // Advance past header + data (padded to 512-byte boundary).
        pos = data_start + ((size + 511) & !511);
    }
    Ok(files)
}

/// Look up an entry in the tar map by filename (last path component).
///
/// The tar may have VFS-style paths (e.g., `c/windows/system32/ntdll.dll`)
/// or flat filenames (e.g., `ntdll.dll`). This searches by matching the
/// last `/`-delimited component.
pub fn find_by_filename<'a>(
    tar_files: &'a BTreeMap<String, Vec<u8>>,
    filename: &str,
) -> Option<(&'a str, &'a Vec<u8>)> {
    let target = filename.to_ascii_lowercase();
    tar_files
        .iter()
        .find(|(k, _)| {
            let basename = k.rsplit('/').next().unwrap_or(k);
            basename == target
        })
        .map(|(k, v)| (k.as_str(), v))
}

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

    eprintln!("[real-dlls] {} DLLs in tar", dll_files.len());

    // Step 1: Rewrite ntdll.dll syscalls.
    // ntdll always gets load slot 0.
    let ntdll_load_va = partition_start + REAL_DLL_OFFSET;
    let trampoline_va = partition_start + TRAMPOLINE_OFFSET;
    let rewrite = if let Some(ntdll_data) = dll_files.get("ntdll.dll") {
        let result =
            ntdll_rewriter::rewrite_ntdll(ntdll_data, ntdll_load_va as u64, trampoline_va as u64);
        eprintln!(
            "[real-dlls] Rewrote {} ntdll syscall stubs ({} identified)",
            result.stubs_rewritten, result.stubs_identified
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

        eprintln!(
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
        eprintln!(
            "[real-dlls] {} unresolved imports (fallback stub):",
            all_unresolved.len()
        );
        for (i, name) in all_unresolved.iter().enumerate() {
            if i >= 30 {
                eprintln!("  ... and {} more", all_unresolved.len() - 30);
                break;
            }
            eprintln!("  {name}");
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
                eprintln!("[real-dlls] Patched {name} at 0x{va:X} -> ret 0x{status:08X}");
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
        stubs_rewritten: rewrite.stubs_rewritten,
        stubs_identified: rewrite.stubs_identified,
        iat_patches: all_patches,
        unresolved_imports: all_unresolved,
    })
}
