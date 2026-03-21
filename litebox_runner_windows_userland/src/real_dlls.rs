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
        if name_lower.ends_with(&target_lower) {
            let sep = if dir_path.ends_with('/') { "" } else { "/" };
            return Some(format!("{dir_path}{sep}{}", entry.name));
        }
        // Collect subdirectories for recursive search.
        // Heuristic: entries without a file extension are likely directories.
        if !entry.name.contains('.') {
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
    eprintln!(
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
