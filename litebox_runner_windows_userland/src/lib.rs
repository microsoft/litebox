// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows userland PE runner for LiteBox.
//!
//! Loads a PE executable into a LiteBox address space using the NT shim,
//! generates stub DLLs (ntdll.dll, kernel32.dll, advapi32.dll, ws2_32.dll),
//! resolves imports, synthesizes PEB/TEB, and runs the guest until it
//! terminates.
//!
//! ## Usage
//!
//! ```text
//! litebox_runner_windows_userland --pe-file hello.exe
//! ```
//!
//! For Phase 1, static PE executables that import from the built-in stub DLLs
//! are supported. The guest uses `syscall` to communicate with the NT shim.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(
    // PE format code inherently involves cross-width casts and integer wrapping.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
)]

extern crate alloc;

mod real_dlls;

use anyhow::{Result, anyhow};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{AddressSpaceProvider, RawConstPointer, RawMutPointer, SystemInfoProvider};
use litebox_common_windows::pe_builder::{ImportDescriptor, ImportFunction, build_test_exe};
use litebox_common_windows::pe_loader::{
    IatPatch, LoadedModule, PeLoadError, PeMemoryMapper, SectionPermissions, load_pe,
    resolve_imports_lenient,
};
use litebox_common_windows::pe_parser::PeParsedFile;
use litebox_common_windows::stub_dlls;
use litebox_platform_multiplex::Platform;
use litebox_shim_windows::peb_teb::{PebTebLayout, PebTebParams, build_peb_teb_bytes};

// FFI for apply_iat_patches (temporary page-protection toggle).
unsafe extern "system" {
    fn VirtualProtect(
        lpAddress: *mut u8,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
}

/// Page size for the Windows userland platform.
const PAGE_SIZE: usize = 4096;

/// Default image base for test EXEs when none is specified.
const DEFAULT_EXE_IMAGE_BASE: u64 = 0x0000_0040_0000;

/// Stack size: 1 MiB (matching Windows default).
const GUEST_STACK_SIZE: usize = 0x0010_0000;

/// DLL load offsets from the VA partition start.
/// Placed at ~508 GiB into the partition to leave room above for
/// MEM_TOP_DOWN heap reservations and below for the EXE and heap.
const NTDLL_LOAD_OFFSET: usize = 0x7F_0000_0000;
const KERNEL32_LOAD_OFFSET: usize = 0x7F_0001_0000;
const ADVAPI32_LOAD_OFFSET: usize = 0x7F_0002_0000;
const WS2_32_LOAD_OFFSET: usize = 0x7F_0003_0000;
const CRYPT32_LOAD_OFFSET: usize = 0x7F_0004_0000;
const IPHLPAPI_LOAD_OFFSET: usize = 0x7F_0005_0000;
const SHELL32_LOAD_OFFSET: usize = 0x7F_0006_0000;
const USER32_LOAD_OFFSET: usize = 0x7F_0007_0000;
const USERENV_LOAD_OFFSET: usize = 0x7F_0008_0000;
const WINMM_LOAD_OFFSET: usize = 0x7F_0009_0000;
const DBGHELP_LOAD_OFFSET: usize = 0x7F_000A_0000;
const OLE32_LOAD_OFFSET: usize = 0x7F_000B_0000;
const FALLBACK_LOAD_OFFSET: usize = 0x7E_F000_0000;

/// PEB/TEB region offset — placed well below the DLL region.
const PEB_TEB_OFFSET: usize = 0x7E_FFF0_0000;

/// Run Windows PE programs with LiteBox.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// Path to the PE executable to run.
    #[arg(long = "pe-file", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub pe_file: Option<PathBuf>,
    /// Run the built-in hello world test instead of a file.
    #[arg(long = "test-hello")]
    pub test_hello: bool,
    /// Connect to a network broker via TCP loopback at the given address
    /// (e.g., "127.0.0.1:9000"). The broker must be listening and speaking
    /// the litebox IPC network protocol (LBNP handshake).
    #[arg(long = "network-broker", value_name = "ADDR")]
    pub network_broker: Option<String>,
    /// Use real System32 DLLs (ntdll.dll, kernel32.dll, etc.) with
    /// rewritten syscalls instead of stub DLLs. Required for complex
    /// applications like node.exe. Requires --dll-tar.
    #[arg(long = "real-dlls")]
    pub real_dlls: bool,
    /// Path to a tar file containing real DLLs (ntdll.dll, kernel32.dll,
    /// etc.) and optionally the main EXE. Used with --real-dlls.
    #[arg(long = "dll-tar", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub dll_tar: Option<PathBuf>,
}

/// Run a Windows PE program with LiteBox.
///
/// # Panics
///
/// Panics if the platform cannot allocate page-aligned memory for the guest
/// stack, PEB/TEB, or PE sections. These are programming errors rather than
/// user-recoverable conditions.
#[allow(clippy::items_after_statements)]
pub fn run(cli_args: CliArgs) -> Result<()> {
    // When --real-dlls is active, the EXE comes from --pe-file or from
    // the tar itself (e.g., "node.exe").
    let pe_data = if cli_args.real_dlls {
        // In real-DLL mode, the EXE can come from --pe-file, or we look
        // for it inside the tar.
        if let Some(pe_path) = &cli_args.pe_file {
            std::fs::read(pe_path)
                .map_err(|e| anyhow!("Could not read PE file at {}: {}", pe_path.display(), e))?
        } else {
            // Will extract from tar below.
            Vec::new()
        }
    } else if cli_args.test_hello {
        build_hello_world_exe()
    } else if let Some(pe_path) = &cli_args.pe_file {
        std::fs::read(pe_path)
            .map_err(|e| anyhow!("Could not read PE file at {}: {}", pe_path.display(), e))?
    } else {
        anyhow::bail!("Must specify --pe-file <path> or --test-hello");
    };

    // Initialize platform.
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    // If a network broker address was provided, connect and attach the IPC
    // stream to the platform before creating the smoltcp Network (which reads
    // from the platform's IPInterfaceProvider).
    if let Some(ref broker_addr) = cli_args.network_broker {
        let stream = connect_to_broker_ipc(broker_addr)?;
        platform.set_ipc_stream(stream);
    }

    let litebox = litebox::LiteBox::new(platform);

    // Create the smoltcp network stack if any network transport is configured.
    let net = if platform.has_network() {
        let mut n = litebox::net::Network::new(&litebox);
        n.set_platform_interaction(litebox::net::PlatformInteraction::Manual);
        Some(Arc::new(std::sync::Mutex::new(n)))
    } else {
        None
    };

    // Allocate guest address space.
    let as_id = platform
        .create_address_space()
        .map_err(|e| anyhow!("Failed to allocate address space: {e:?}"))?;
    let as_range = platform
        .address_space_range(as_id)
        .map_err(|e| anyhow!("Failed to get address space range: {e:?}"))?;
    let guest_va_start = as_range.start;
    let guest_va_end = as_range.end;

    // Compute actual DLL addresses from partition start + offsets.
    #[allow(non_snake_case)]
    let NTDLL_LOAD_BASE = guest_va_start + NTDLL_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let KERNEL32_LOAD_BASE = guest_va_start + KERNEL32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let ADVAPI32_LOAD_BASE = guest_va_start + ADVAPI32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let WS2_32_LOAD_BASE = guest_va_start + WS2_32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let CRYPT32_LOAD_BASE = guest_va_start + CRYPT32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let IPHLPAPI_LOAD_BASE = guest_va_start + IPHLPAPI_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let SHELL32_LOAD_BASE = guest_va_start + SHELL32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let USER32_LOAD_BASE = guest_va_start + USER32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let USERENV_LOAD_BASE = guest_va_start + USERENV_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let WINMM_LOAD_BASE = guest_va_start + WINMM_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let DBGHELP_LOAD_BASE = guest_va_start + DBGHELP_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let OLE32_LOAD_BASE = guest_va_start + OLE32_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let FALLBACK_LOAD_BASE = guest_va_start + FALLBACK_LOAD_OFFSET;
    #[allow(non_snake_case)]
    let PEB_TEB_BASE = guest_va_start + PEB_TEB_OFFSET;

    let pm = litebox::mm::PageManager::new(&litebox, as_range);

    // Create the process state that will be shared with the shim.
    // The runner uses pm via process_state.pm for all mapping operations.
    let process_state = alloc::sync::Arc::new(litebox_shim_windows::NtProcessState::new(pm));

    // ── Loading path ────────────────────────────────────────────────
    // Two modes: stub DLLs (default) or real DLLs (--real-dlls).
    // Both produce the same outputs needed by the rest of the function.
    struct LoadResult {
        exe_entry_point: usize,
        exe_image_base: usize,
        exe_image_size: usize,
        module_bases: Vec<litebox_shim_windows::ModuleBase>,
        /// For ntdll-driven init: VA of LdrInitializeThunk (thread entry point).
        ldr_init_thunk_va: Option<usize>,
        /// For ntdll-driven init: VA of RtlUserThreadStart (CONTEXT.Rip).
        rtl_user_thread_start_va: Option<usize>,
        /// For ntdll-driven init: tar file data for serving DLLs via NtOpenFile.
        dll_tar_files: Option<std::collections::BTreeMap<String, Vec<u8>>>,
        /// Mapping from real Windows syscall numbers to NtSyscallId.
        syscall_map: Option<litebox_common_windows::NtSyscallMap>,
        /// Unhandled stub names for debug logging of unknown syscalls.
        unhandled_stubs: Vec<(u32, String)>,
    }

    let mut mapper = PageManagerMapper {
        pm: &process_state.pm,
    };

    let load_result = if cli_args.real_dlls {
        // ── ntdll-driven init path ────────────────────────────────
        // Load only ntdll (with rewritten syscalls) and the EXE.
        // ntdll's LdrpInitialize will load all other DLLs via syscalls
        // that we intercept and serve from the tar file.
        let tar_path = cli_args
            .dll_tar
            .as_ref()
            .ok_or_else(|| anyhow!("--real-dlls requires --dll-tar <path>"))?;
        let tar_data = std::fs::read(tar_path)
            .map_err(|e| anyhow!("Could not read DLL tar at {}: {e}", tar_path.display()))?;
        #[allow(clippy::cast_precision_loss)]
        let tar_size_mb = tar_data.len() as f64 / 1_048_576.0;
        eprintln!(
            "[real-dlls] Read tar: {} ({tar_size_mb:.1} MB)",
            tar_path.display(),
        );
        let tar_files = real_dlls::read_tar(&tar_data)?;
        eprintln!("[real-dlls] Tar entries: {}", tar_files.len());
        for (name, data) in &tar_files {
            eprintln!("  {name}: {} bytes", data.len());
        }

        // If no --pe-file, look for an EXE inside the tar.
        let pe_data = if pe_data.is_empty() {
            let exe_name = tar_files
                .keys()
                .find(|k| {
                    k.get(k.len().saturating_sub(4)..)
                        .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe"))
                })
                .ok_or_else(|| anyhow!("No --pe-file and no .exe found in tar"))?
                .clone();
            eprintln!("[real-dlls] Using {exe_name} from tar");
            tar_files[&exe_name].clone()
        } else {
            pe_data
        };

        // Parse and load the EXE.
        let exe_parsed = PeParsedFile::parse(&pe_data)
            .map_err(|e| anyhow!("Failed to parse PE executable: {e}"))?;

        let preferred_base = exe_parsed.image_base as usize;
        let exe_base = if preferred_base >= guest_va_start && preferred_base < guest_va_end {
            preferred_base
        } else {
            let base = (guest_va_start + 0xFFFF) & !0xFFFF;
            eprintln!("[real-dlls] Rebasing EXE from 0x{preferred_base:X} to 0x{base:X}");
            base
        };
        let mut pm_mapper = PmMapper::new(&process_state.pm);
        pm_mapper
            .pre_reserve(exe_base, exe_parsed.size_of_image as usize)
            .map_err(|e| anyhow!("Failed to reserve VA for EXE: {e:?}"))?;
        let exe_info = load_pe(&exe_parsed, &pe_data, exe_base, &mut pm_mapper)
            .map_err(|e| anyhow!("Failed to load PE executable: {e}"))?;

        // Patch the in-memory PE header's ImageBase to match the actual load
        // address. Without this, ntdll's loader would see ImageBase != DllBase
        // and apply relocations *again* (on top of the runner's), causing
        // double-relocation corruption.
        {
            use litebox::platform::RawConstPointer as _;
            let hdr_ptr = <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::<u8>::from_usize(exe_base);
            unsafe {
                let _ = process_state.pm.make_pages_writable(hdr_ptr, PAGE_SIZE);
                let pe_sig_off = *(exe_base as *const u32).byte_add(0x3C) as usize;
                let opt_hdr = exe_base + pe_sig_off + 0x18;
                let image_base_ptr = (opt_hdr + 0x18) as *mut u64;
                core::ptr::write(image_base_ptr, exe_base as u64);
                let _ = process_state.pm.make_pages_readable(hdr_ptr, PAGE_SIZE);
            }
        }

        eprintln!(
            "[real-dlls] EXE loaded at 0x{:X}, entry=0x{:X}",
            exe_info.image_base, exe_info.entry_point
        );

        // Load ntdll with rewritten syscalls + find LdrInitializeThunk.
        let result = real_dlls::load_ntdll_for_init(&tar_files, &mut pm_mapper, guest_va_start)?;

        // Map the trampoline page.
        let syscall_entry = platform.get_syscall_entry_point() as u64;
        let gs_table_ptr = platform.guest_gs_table_ptr() as u64;
        let tramp_va = result.trampoline_va;
        let entry_off = result.entry_ptr_offset;
        let gs_off = result.gs_table_ptr_offset;

        let mut tramp_data = result.trampoline;
        tramp_data[entry_off..entry_off + 8].copy_from_slice(&syscall_entry.to_le_bytes());
        tramp_data[gs_off..gs_off + 8].copy_from_slice(&gs_table_ptr.to_le_bytes());

        pm_mapper
            .pre_reserve(tramp_va, PAGE_SIZE)
            .map_err(|e| anyhow!("Failed to reserve trampoline page: {e:?}"))?;
        pm_mapper
            .map_section(
                tramp_va,
                &tramp_data,
                PAGE_SIZE,
                SectionPermissions::ReadExecute,
            )
            .map_err(|e| anyhow!("Failed to map trampoline: {e:?}"))?;

        eprintln!(
            "[real-dlls] Trampoline at 0x{tramp_va:X}, entry ptr at +0x{entry_off:X} = 0x{syscall_entry:X}"
        );
        eprintln!(
            "[real-dlls] {} stubs rewritten ({} identified)",
            result.stubs_rewritten, result.stubs_identified
        );

        let module_bases = vec![
            litebox_shim_windows::ModuleBase {
                name: cli_args
                    .pe_file
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .and_then(|f| f.to_str())
                    .unwrap_or("app.exe")
                    .to_string(),
                path: cli_args
                    .pe_file
                    .as_ref()
                    .and_then(|p| p.canonicalize().ok())
                    .and_then(|p| p.to_str().map(std::string::ToString::to_string))
                    .unwrap_or_else(|| String::from("C:\\app.exe")),
                base_address: exe_info.image_base,
                image_size: exe_info.image_size,
            },
            litebox_shim_windows::ModuleBase {
                name: String::from("ntdll.dll"),
                path: String::from("C:\\Windows\\System32\\ntdll.dll"),
                base_address: result.ntdll.base_address,
                image_size: result.ntdll.image_size,
            },
        ];

        LoadResult {
            exe_entry_point: exe_info.entry_point,
            exe_image_base: exe_info.image_base,
            exe_image_size: exe_info.image_size,
            module_bases,
            ldr_init_thunk_va: Some(result.ldr_init_thunk_va),
            rtl_user_thread_start_va: Some(result.rtl_user_thread_start_va),
            dll_tar_files: Some(tar_files),
            syscall_map: Some(result.syscall_map),
            unhandled_stubs: result.unhandled_stubs,
        }
    } else {
        // ── Stub DLL path (original) ───────────────────────────────
        let syscall_entry = platform.get_syscall_entry_point() as u64;
        let gs_table_ptr = platform.guest_gs_table_ptr() as u64;
        let ntdll_bytes =
            stub_dlls::build_ntdll_for(NTDLL_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let kernel32_bytes =
            stub_dlls::build_kernel32_for(KERNEL32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let advapi32_bytes =
            stub_dlls::build_advapi32_for(ADVAPI32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let ws2_32_bytes =
            stub_dlls::build_ws2_32_for(WS2_32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let crypt32_bytes =
            stub_dlls::build_crypt32_for(CRYPT32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let iphlpapi_bytes =
            stub_dlls::build_iphlpapi_for(IPHLPAPI_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let shell32_bytes =
            stub_dlls::build_shell32_for(SHELL32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let user32_bytes =
            stub_dlls::build_user32_for(USER32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let userenv_bytes =
            stub_dlls::build_userenv_for(USERENV_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let winmm_bytes =
            stub_dlls::build_winmm_for(WINMM_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let dbghelp_bytes =
            stub_dlls::build_dbghelp_for(DBGHELP_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let ole32_bytes =
            stub_dlls::build_ole32_for(OLE32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);

        let ntdll_parsed = PeParsedFile::parse(&ntdll_bytes)
            .map_err(|e| anyhow!("Failed to parse ntdll stub: {e}"))?;
        let kernel32_parsed = PeParsedFile::parse(&kernel32_bytes)
            .map_err(|e| anyhow!("Failed to parse kernel32 stub: {e}"))?;
        let advapi32_parsed = PeParsedFile::parse(&advapi32_bytes)
            .map_err(|e| anyhow!("Failed to parse advapi32 stub: {e}"))?;
        let ws2_32_parsed = PeParsedFile::parse(&ws2_32_bytes)
            .map_err(|e| anyhow!("Failed to parse ws2_32 stub: {e}"))?;
        let crypt32_parsed = PeParsedFile::parse(&crypt32_bytes)
            .map_err(|e| anyhow!("Failed to parse crypt32 stub: {e}"))?;
        let iphlpapi_parsed = PeParsedFile::parse(&iphlpapi_bytes)
            .map_err(|e| anyhow!("Failed to parse iphlpapi stub: {e}"))?;
        let shell32_parsed = PeParsedFile::parse(&shell32_bytes)
            .map_err(|e| anyhow!("Failed to parse shell32 stub: {e}"))?;
        let user32_parsed = PeParsedFile::parse(&user32_bytes)
            .map_err(|e| anyhow!("Failed to parse user32 stub: {e}"))?;
        let userenv_parsed = PeParsedFile::parse(&userenv_bytes)
            .map_err(|e| anyhow!("Failed to parse userenv stub: {e}"))?;
        let winmm_parsed = PeParsedFile::parse(&winmm_bytes)
            .map_err(|e| anyhow!("Failed to parse winmm stub: {e}"))?;
        let dbghelp_parsed = PeParsedFile::parse(&dbghelp_bytes)
            .map_err(|e| anyhow!("Failed to parse dbghelp stub: {e}"))?;
        let ole32_parsed = PeParsedFile::parse(&ole32_bytes)
            .map_err(|e| anyhow!("Failed to parse ole32 stub: {e}"))?;

        let ntdll_info = load_pe(&ntdll_parsed, &ntdll_bytes, NTDLL_LOAD_BASE, &mut mapper)
            .map_err(|e| anyhow!("Failed to load ntdll stub: {e}"))?;
        let kernel32_info = load_pe(
            &kernel32_parsed,
            &kernel32_bytes,
            KERNEL32_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load kernel32 stub: {e}"))?;
        let advapi32_info = load_pe(
            &advapi32_parsed,
            &advapi32_bytes,
            ADVAPI32_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load advapi32 stub: {e}"))?;
        let ws2_32_info = load_pe(&ws2_32_parsed, &ws2_32_bytes, WS2_32_LOAD_BASE, &mut mapper)
            .map_err(|e| anyhow!("Failed to load ws2_32 stub: {e}"))?;
        let crypt32_info = load_pe(
            &crypt32_parsed,
            &crypt32_bytes,
            CRYPT32_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load crypt32 stub: {e}"))?;
        let iphlpapi_info = load_pe(
            &iphlpapi_parsed,
            &iphlpapi_bytes,
            IPHLPAPI_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load iphlpapi stub: {e}"))?;
        let shell32_info = load_pe(
            &shell32_parsed,
            &shell32_bytes,
            SHELL32_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load shell32 stub: {e}"))?;
        let user32_info = load_pe(&user32_parsed, &user32_bytes, USER32_LOAD_BASE, &mut mapper)
            .map_err(|e| anyhow!("Failed to load user32 stub: {e}"))?;
        let userenv_info = load_pe(
            &userenv_parsed,
            &userenv_bytes,
            USERENV_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load userenv stub: {e}"))?;
        let winmm_info = load_pe(&winmm_parsed, &winmm_bytes, WINMM_LOAD_BASE, &mut mapper)
            .map_err(|e| anyhow!("Failed to load winmm stub: {e}"))?;
        let dbghelp_info = load_pe(
            &dbghelp_parsed,
            &dbghelp_bytes,
            DBGHELP_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load dbghelp stub: {e}"))?;
        let ole32_info = load_pe(&ole32_parsed, &ole32_bytes, OLE32_LOAD_BASE, &mut mapper)
            .map_err(|e| anyhow!("Failed to load ole32 stub: {e}"))?;

        // Build fallback "return 0" stub for unresolved imports.
        let fallback_bytes =
            stub_dlls::build_fallback_for(FALLBACK_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
        let fallback_parsed = PeParsedFile::parse(&fallback_bytes)
            .map_err(|e| anyhow!("Failed to parse fallback stub: {e}"))?;
        let fallback_info = load_pe(
            &fallback_parsed,
            &fallback_bytes,
            FALLBACK_LOAD_BASE,
            &mut mapper,
        )
        .map_err(|e| anyhow!("Failed to load fallback stub: {e}"))?;
        // The fallback VA is the address of the single "__fallback_stub" export.
        let fallback_va = {
            let exports = fallback_parsed.exports(&fallback_bytes);
            let rva = exports
                .first()
                .expect("fallback stub must have one export")
                .rva;
            (fallback_info.image_base + rva as usize) as u64
        };

        if cfg!(debug_assertions) {
            eprintln!(
                "Stub DLLs loaded: ntdll=0x{:X} kernel32=0x{:X} advapi32=0x{:X} ws2_32=0x{:X} +8 more",
                ntdll_info.image_base,
                kernel32_info.image_base,
                advapi32_info.image_base,
                ws2_32_info.image_base
            );
        }

        // Parse and load the main EXE.
        let exe_parsed = PeParsedFile::parse(&pe_data)
            .map_err(|e| anyhow!("Failed to parse PE executable: {e}"))?;

        // If the PE preferred base is outside the guest VA partition, rebase it
        // to the start of the partition (aligned to 64KB as Windows requires).
        let preferred_base = exe_parsed.image_base as usize;
        let exe_base = if preferred_base >= guest_va_start && preferred_base < guest_va_end {
            preferred_base
        } else {
            // Rebase to beginning of guest VA partition, 64KB aligned.
            let base = (guest_va_start + 0xFFFF) & !0xFFFF;
            if cfg!(debug_assertions) {
                eprintln!(
                    "Rebasing EXE from 0x{preferred_base:X} to 0x{base:X} (outside guest VA 0x{guest_va_start:X}..0x{guest_va_end:X})"
                );
            }
            base
        };
        let exe_info = load_pe(&exe_parsed, &pe_data, exe_base, &mut mapper)
            .map_err(|e| anyhow!("Failed to load PE executable: {e}"))?;

        if cfg!(debug_assertions) {
            eprintln!(
                "EXE loaded at 0x{:X}, entry point at 0x{:X}",
                exe_info.image_base, exe_info.entry_point
            );
        }

        // Resolve imports.
        let modules = [
            LoadedModule {
                name: "ntdll.dll",
                base_address: ntdll_info.image_base,
                pe_data: &ntdll_bytes,
                parsed: &ntdll_parsed,
            },
            LoadedModule {
                name: "kernel32.dll",
                base_address: kernel32_info.image_base,
                pe_data: &kernel32_bytes,
                parsed: &kernel32_parsed,
            },
            LoadedModule {
                name: "advapi32.dll",
                base_address: advapi32_info.image_base,
                pe_data: &advapi32_bytes,
                parsed: &advapi32_parsed,
            },
            LoadedModule {
                name: "ws2_32.dll",
                base_address: ws2_32_info.image_base,
                pe_data: &ws2_32_bytes,
                parsed: &ws2_32_parsed,
            },
            LoadedModule {
                name: "crypt32.dll",
                base_address: crypt32_info.image_base,
                pe_data: &crypt32_bytes,
                parsed: &crypt32_parsed,
            },
            LoadedModule {
                name: "iphlpapi.dll",
                base_address: iphlpapi_info.image_base,
                pe_data: &iphlpapi_bytes,
                parsed: &iphlpapi_parsed,
            },
            LoadedModule {
                name: "shell32.dll",
                base_address: shell32_info.image_base,
                pe_data: &shell32_bytes,
                parsed: &shell32_parsed,
            },
            LoadedModule {
                name: "user32.dll",
                base_address: user32_info.image_base,
                pe_data: &user32_bytes,
                parsed: &user32_parsed,
            },
            LoadedModule {
                name: "userenv.dll",
                base_address: userenv_info.image_base,
                pe_data: &userenv_bytes,
                parsed: &userenv_parsed,
            },
            LoadedModule {
                name: "winmm.dll",
                base_address: winmm_info.image_base,
                pe_data: &winmm_bytes,
                parsed: &winmm_parsed,
            },
            LoadedModule {
                name: "dbghelp.dll",
                base_address: dbghelp_info.image_base,
                pe_data: &dbghelp_bytes,
                parsed: &dbghelp_parsed,
            },
            LoadedModule {
                name: "ole32.dll",
                base_address: ole32_info.image_base,
                pe_data: &ole32_bytes,
                parsed: &ole32_parsed,
            },
        ];

        eprintln!("resolving imports...");
        let (patches, skipped) =
            resolve_imports_lenient(&exe_parsed, &pe_data, exe_base, &modules, fallback_va)
                .map_err(|e| anyhow!("Failed to resolve imports: {e}"))?;
        if !skipped.is_empty() {
            eprintln!(
                "[NT shim] {} unresolved imports patched with fallback stub:",
                skipped.len()
            );
            for name in &skipped {
                eprintln!("  {name}");
            }
        }

        // Apply IAT patches to guest memory.
        apply_iat_patches(&process_state.pm, &patches);

        if cfg!(debug_assertions) {
            eprintln!("Resolved {} import patches", patches.len());
            for p in &patches {
                let current_val = unsafe { *(p.iat_va as *const u64) };
                eprintln!(
                    "  IAT[0x{:X}] = 0x{:X} (resolved=0x{:X})",
                    p.iat_va, current_val, p.resolved_va
                );
            }
        }

        LoadResult {
            exe_entry_point: exe_info.entry_point,
            exe_image_base: exe_info.image_base,
            exe_image_size: exe_info.image_size,
            module_bases: vec![
                litebox_shim_windows::ModuleBase {
                    name: if let Some(pe_path) = &cli_args.pe_file {
                        pe_path
                            .file_name()
                            .and_then(|f| f.to_str())
                            .unwrap_or("unknown.exe")
                            .to_string()
                    } else {
                        String::from("hello.exe")
                    },
                    path: if let Some(pe_path) = &cli_args.pe_file {
                        pe_path
                            .canonicalize()
                            .ok()
                            .and_then(|p| p.to_str().map(std::string::ToString::to_string))
                            .unwrap_or_else(|| {
                                pe_path.to_str().unwrap_or("C:\\app.exe").to_string()
                            })
                    } else {
                        String::from("C:\\hello.exe")
                    },
                    base_address: exe_info.image_base,
                    image_size: exe_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("ntdll.dll"),
                    path: String::from("C:\\Windows\\System32\\ntdll.dll"),
                    base_address: NTDLL_LOAD_BASE,
                    image_size: ntdll_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("kernel32.dll"),
                    path: String::from("C:\\Windows\\System32\\kernel32.dll"),
                    base_address: KERNEL32_LOAD_BASE,
                    image_size: kernel32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("advapi32.dll"),
                    path: String::from("C:\\Windows\\System32\\advapi32.dll"),
                    base_address: ADVAPI32_LOAD_BASE,
                    image_size: advapi32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("ws2_32.dll"),
                    path: String::from("C:\\Windows\\System32\\ws2_32.dll"),
                    base_address: WS2_32_LOAD_BASE,
                    image_size: ws2_32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("crypt32.dll"),
                    path: String::from("C:\\Windows\\System32\\crypt32.dll"),
                    base_address: CRYPT32_LOAD_BASE,
                    image_size: crypt32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("iphlpapi.dll"),
                    path: String::from("C:\\Windows\\System32\\iphlpapi.dll"),
                    base_address: IPHLPAPI_LOAD_BASE,
                    image_size: iphlpapi_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("shell32.dll"),
                    path: String::from("C:\\Windows\\System32\\shell32.dll"),
                    base_address: SHELL32_LOAD_BASE,
                    image_size: shell32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("user32.dll"),
                    path: String::from("C:\\Windows\\System32\\user32.dll"),
                    base_address: USER32_LOAD_BASE,
                    image_size: user32_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("userenv.dll"),
                    path: String::from("C:\\Windows\\System32\\userenv.dll"),
                    base_address: USERENV_LOAD_BASE,
                    image_size: userenv_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("winmm.dll"),
                    path: String::from("C:\\Windows\\System32\\winmm.dll"),
                    base_address: WINMM_LOAD_BASE,
                    image_size: winmm_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("dbghelp.dll"),
                    path: String::from("C:\\Windows\\System32\\dbghelp.dll"),
                    base_address: DBGHELP_LOAD_BASE,
                    image_size: dbghelp_info.image_size,
                },
                litebox_shim_windows::ModuleBase {
                    name: String::from("ole32.dll"),
                    path: String::from("C:\\Windows\\System32\\ole32.dll"),
                    base_address: OLE32_LOAD_BASE,
                    image_size: ole32_info.image_size,
                },
            ],
            ldr_init_thunk_va: None,
            rtl_user_thread_start_va: None,
            dll_tar_files: None,
            syscall_map: Some(litebox_common_windows::NtSyscallMap::identity()),
            unhandled_stubs: Vec::new(),
        }
    }; // end if real_dlls / else

    // ── Common path: stack, PEB/TEB, shim, execution ────────────
    // Allocate guest stack.
    let stack_size = NonZeroPageSize::<PAGE_SIZE>::new(GUEST_STACK_SIZE)
        .expect("stack size must be page-aligned");
    let stack_base_ptr = unsafe {
        process_state.pm.create_writable_pages(
            None,
            stack_size,
            CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |_ptr| Ok(0), // zero-fill
        )
    }
    .map_err(|e| anyhow!("Failed to allocate guest stack: {e:?}"))?;
    let stack_base = stack_base_ptr.as_usize();
    let stack_alloc_top = stack_base + GUEST_STACK_SIZE;
    // Reserve space at the top of the stack for shadow space and alignment.
    // The PE entry point is a tail-call target (`jmp __scrt_common_main_seh`)
    // that may write to [rsp+8..rsp+20h] (shadow space). The OS normally
    // provides this headroom; we simulate it by lowering RSP.
    // Layout: [return_addr=0][shadow0][shadow1][shadow2][shadow3]
    // 8 bytes return addr + 32 bytes shadow = 40 bytes.
    let stack_top = stack_alloc_top - 0x28;

    if cfg!(debug_assertions) {
        eprintln!("Stack: base=0x{stack_base:X}, top=0x{stack_top:X}");
    }

    // Synthesize PEB/TEB.
    let mut shim =
        litebox_shim_windows::NtShimEntrypoints::new(alloc::sync::Arc::clone(&process_state));
    if let Some(map) = load_result.syscall_map {
        shim.set_syscall_map(map);
    }
    if !load_result.unhandled_stubs.is_empty() {
        shim.set_unhandled_stubs(load_result.unhandled_stubs);
    }
    let (stdin_h, stdout_h, stderr_h) = shim.stdio_handles();

    let peb_teb_layout = PebTebLayout::at_base(PEB_TEB_BASE);

    // With real DLLs, ntdll's RtlAllocateHeap needs a real Windows heap.
    // Create one via the host's HeapCreate. With stub DLLs, heap is handled
    // by the shim's K32 pseudo-syscalls so 0 is fine.
    let process_heap = if cli_args.real_dlls {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn HeapCreate(
                fl_options: u32,
                dw_initial_size: usize,
                dw_max_size: usize,
            ) -> *mut core::ffi::c_void;
        }
        let h = unsafe { HeapCreate(0, 0, 0) };
        assert!(!h.is_null(), "HeapCreate failed");
        h as usize
    } else {
        0
    };

    // Derive EXE names for PEB/TEB LDR entries from the actual PE file path.
    let (exe_full_path_str, exe_base_name_str) = if let Some(pe_path) = &cli_args.pe_file {
        let canon = pe_path
            .canonicalize()
            .ok()
            .and_then(|p| p.to_str().map(std::string::ToString::to_string));
        let full = canon.unwrap_or_else(|| {
            pe_path
                .to_str()
                .unwrap_or("C:\\app\\unknown.exe")
                .to_string()
        });
        // Strip \\?\ prefix that canonicalize adds on Windows
        let full = full.strip_prefix("\\\\?\\").unwrap_or(&full).to_string();
        let base = pe_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown.exe")
            .to_string();
        (full, base)
    } else {
        ("C:\\app\\hello.exe".to_string(), "hello.exe".to_string())
    };

    // Read the host's API set map address from the host PEB. The guest runs
    // in the same address space, so the host's map is directly accessible.
    #[allow(clippy::cast_ptr_alignment)]
    let host_api_set_map: usize = unsafe {
        let host_peb: *const u8;
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) host_peb, options(nostack, readonly));
        *host_peb.add(0x68).cast::<usize>()
    };
    eprintln!("Host ApiSetMap at: 0x{host_api_set_map:X}");

    let peb_teb_params = PebTebParams {
        stack_base: stack_alloc_top,
        stack_limit: stack_base,
        image_base: load_result.exe_image_base,
        image_size: load_result.exe_image_size,
        process_heap,
        command_line_wide: exe_base_name_str.encode_utf16().collect(),
        image_path_wide: format!("\\??\\{exe_full_path_str}")
            .encode_utf16()
            .collect(),
        exe_full_path: exe_full_path_str.encode_utf16().collect(),
        exe_base_name: exe_base_name_str.encode_utf16().collect(),
        stdin_handle: u64::from(stdin_h),
        stdout_handle: u64::from(stdout_h),
        stderr_handle: u64::from(stderr_h),
        ntdll_base: load_result
            .module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.base_address),
        ntdll_size: load_result
            .module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.image_size),
        // Synthetic IDs matching what NtQueryInformationProcess returns.
        process_id: 1000,
        thread_id: 1004,
        api_set_map: host_api_set_map,
    };
    let peb_teb_bytes = build_peb_teb_bytes(&peb_teb_layout, &peb_teb_params);

    // Map PEB/TEB region as RW.
    let peb_teb_size = NonZeroPageSize::<PAGE_SIZE>::new(peb_teb_layout.total_size)
        .expect("PEB/TEB size must be page-aligned");
    let peb_teb_addr =
        NonZeroAddress::<PAGE_SIZE>::new(PEB_TEB_BASE).expect("PEB/TEB base must be page-aligned");
    unsafe {
        process_state.pm.create_writable_pages(
            Some(peb_teb_addr),
            peb_teb_size,
            CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY,
            |ptr| {
                ptr.copy_from_slice(0, &peb_teb_bytes)
                    .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                Ok(peb_teb_layout.total_size)
            },
        )
    }
    .map_err(|e| anyhow!("Failed to map PEB/TEB: {e:?}"))?;

    if cfg!(debug_assertions) {
        eprintln!(
            "PEB/TEB mapped at 0x{:X} (TEB=0x{:X}, PEB=0x{:X})",
            PEB_TEB_BASE, peb_teb_layout.teb_va, peb_teb_layout.peb_va
        );
        // Dump the LDR module entries to verify correctness.
        let ldr_va = peb_teb_layout.ldr_data_va;
        unsafe {
            let peb_image_base = core::ptr::read((peb_teb_layout.peb_va + 0x10) as *const u64);
            let peb_ldr_ptr = core::ptr::read((peb_teb_layout.peb_va + 0x18) as *const u64);
            eprintln!(
                "[LDR-verify] PEB.ImageBaseAddress=0x{peb_image_base:X}, PEB.Ldr=0x{peb_ldr_ptr:X} (expected 0x{ldr_va:X})"
            );

            // EXE entry at ldr_va + 0x60
            let exe_dll_base = core::ptr::read((ldr_va + 0x60 + 0x30) as *const u64);
            let exe_size = core::ptr::read((ldr_va + 0x60 + 0x40) as *const u32);
            let exe_load_order_next = core::ptr::read((ldr_va + 0x60) as *const u64);
            let exe_load_order_prev = core::ptr::read((ldr_va + 0x60 + 0x08) as *const u64);
            eprintln!(
                "[LDR-verify] EXE entry(0x{:X}): DllBase=0x{exe_dll_base:X} SizeOfImage=0x{exe_size:X} Flink=0x{exe_load_order_next:X} Blink=0x{exe_load_order_prev:X}",
                ldr_va + 0x60
            );

            // ntdll entry at ldr_va + 0x180
            let ntdll_dll_base = core::ptr::read((ldr_va + 0x180 + 0x30) as *const u64);
            let ntdll_size = core::ptr::read((ldr_va + 0x180 + 0x40) as *const u32);
            let ntdll_load_order_next = core::ptr::read((ldr_va + 0x180) as *const u64);
            let ntdll_load_order_prev = core::ptr::read((ldr_va + 0x180 + 0x08) as *const u64);
            eprintln!(
                "[LDR-verify] ntdll entry(0x{:X}): DllBase=0x{ntdll_dll_base:X} SizeOfImage=0x{ntdll_size:X} Flink=0x{ntdll_load_order_next:X} Blink=0x{ntdll_load_order_prev:X}",
                ldr_va + 0x180
            );

            // Head pointers
            let load_order_head_next = core::ptr::read((ldr_va + 0x10) as *const u64);
            let load_order_head_prev = core::ptr::read((ldr_va + 0x18) as *const u64);
            eprintln!(
                "[LDR-verify] InLoadOrderModuleList head(0x{:X}): Flink=0x{load_order_head_next:X} Blink=0x{load_order_head_prev:X}",
                ldr_va + 0x10
            );
        }
    }

    // Derive the EXE path for bookkeeping.
    let exe_full_path = load_result
        .module_bases
        .first()
        .map_or_else(|| String::from("C:\\app.exe"), |m| m.path.clone());

    // For ntdll-driven init, build a CONTEXT on the guest stack and set
    // the entry point to LdrInitializeThunk instead of the EXE entry.
    let (effective_entry_point, effective_stack_top, context_ptr_arg, ntdll_base_arg) = if let (
        Some(ldr_init_va),
        Some(rtl_uts_va),
    ) = (
        load_result.ldr_init_thunk_va,
        load_result.rtl_user_thread_start_va,
    ) {
        // Windows x64 CONTEXT structure layout (1232 = 0x4D0 bytes).
        const CONTEXT_SIZE: usize = 0x4D0;
        // CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
        const CONTEXT_FULL: u32 = 0x10_000B;

        // Place CONTEXT at the top of the stack (16-byte aligned).
        let context_va = (stack_alloc_top - CONTEXT_SIZE) & !0xF;
        // LdrInitializeThunk's own stack: below the CONTEXT with shadow space.
        let ldr_rsp = context_va - 0x28;

        // Build the CONTEXT that LdrInitializeThunk will pass to NtContinue
        // after initialization is complete. This describes the post-init state.
        let mut ctx_bytes = vec![0u8; CONTEXT_SIZE];
        // ContextFlags at offset 0x30
        ctx_bytes[0x30..0x34].copy_from_slice(&CONTEXT_FULL.to_le_bytes());
        // EFlags at 0x44: IF + reserved bit 1
        ctx_bytes[0x44..0x48].copy_from_slice(&0x202u32.to_le_bytes());
        // SegCs at 0x38 = 0x33 (user-mode 64-bit CS)
        ctx_bytes[0x38..0x3A].copy_from_slice(&0x33u16.to_le_bytes());
        // SegSs at 0x42 = 0x2B (user-mode SS)
        ctx_bytes[0x42..0x44].copy_from_slice(&0x2Bu16.to_le_bytes());
        // Rcx at 0x80 = EXE entry point (first param to RtlUserThreadStart)
        ctx_bytes[0x80..0x88].copy_from_slice(&(load_result.exe_entry_point as u64).to_le_bytes());
        // Rdx at 0x88 = 0 (second param: thread parameter)
        ctx_bytes[0x88..0x90].copy_from_slice(&0u64.to_le_bytes());
        // Rsp at 0x98 = clean stack below the context
        ctx_bytes[0x98..0xA0].copy_from_slice(&((context_va - 0x200) as u64).to_le_bytes());
        // Rip at 0xF8 = RtlUserThreadStart
        ctx_bytes[0xF8..0x100].copy_from_slice(&(rtl_uts_va as u64).to_le_bytes());
        // MxCsr at 0x34 = default value (0x1F80)
        ctx_bytes[0x34..0x38].copy_from_slice(&0x1F80u32.to_le_bytes());

        // Write CONTEXT bytes to guest stack memory.
        unsafe {
            core::ptr::copy_nonoverlapping(ctx_bytes.as_ptr(), context_va as *mut u8, CONTEXT_SIZE);
        }

        // ntdll base address for the 2nd parameter to LdrInitializeThunk.
        let ntdll_base = load_result
            .module_bases
            .iter()
            .find(|m| m.name == "ntdll.dll")
            .map_or(0, |m| m.base_address);

        eprintln!(
            "[ntdll-init] CONTEXT at 0x{context_va:X} (Rip=0x{rtl_uts_va:X}, \
                 Rcx=0x{:X}), LdrInitializeThunk at 0x{ldr_init_va:X}, RSP=0x{ldr_rsp:X}, \
                 ntdll_base=0x{ntdll_base:X}",
            load_result.exe_entry_point
        );

        (ldr_init_va, ldr_rsp, Some(context_va), Some(ntdll_base))
    } else {
        // Stub DLL path: jump directly to EXE entry.
        (load_result.exe_entry_point, stack_top, None, None)
    };

    // Set up initial thread state.
    shim.set_init_state(litebox_shim_windows::NtInitState {
        entry_point: effective_entry_point,
        stack_top: effective_stack_top,
        teb_va: peb_teb_layout.teb_va,
        peb_va: peb_teb_layout.peb_va,
        image_base: load_result.exe_image_base,
        process_params_va: peb_teb_layout.process_params_va,
        cmdline_ansi_va: peb_teb_layout.cmdline_ansi_buffer_va,
        env_block_va: peb_teb_layout.env_block_va,
        module_bases: load_result.module_bases,
        guest_va_start,
        guest_va_end,
        exe_path: exe_full_path,
        initial_rcx: context_ptr_arg,
        initial_rdx: ntdll_base_arg,
    });

    // Pass tar files to the shim so it can serve DLLs via NtOpenFile.
    if let Some(tar_files) = load_result.dll_tar_files {
        shim.set_dll_tar_files(tar_files);
    }

    // Attach the network stack to the shim for WinSock syscall dispatch.
    if let Some(ref net_arc) = net {
        shim.set_network(alloc::sync::Arc::clone(net_arc));
    }

    // Start the network worker thread if networking is configured.
    let shutdown = Arc::new(core::sync::atomic::AtomicBool::new(false));
    let network_thread = start_network_worker(net.as_ref(), &shutdown);

    // Run the guest.
    // Tell the platform to set GS = guest TEB before entering guest code.
    litebox_platform_windows_userland::WindowsUserland::set_guest_gs_base(
        peb_teb_layout.teb_va as u64,
    );
    let mut ctx = litebox_common_linux::ExecutionContext::default();

    // Debug watchdog: after 2 seconds, suspend the thread and dump RIP.
    #[cfg(debug_assertions)]
    let _watchdog = if cli_args.real_dlls {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentThread() -> *mut core::ffi::c_void;
            fn SuspendThread(h: *mut core::ffi::c_void) -> u32;
            fn ResumeThread(h: *mut core::ffi::c_void) -> u32;
            fn GetThreadContext(h: *mut core::ffi::c_void, ctx: *mut u8) -> i32;
            fn DuplicateHandle(
                src_proc: *mut core::ffi::c_void,
                src: *mut core::ffi::c_void,
                dst_proc: *mut core::ffi::c_void,
                dst: *mut *mut core::ffi::c_void,
                access: u32,
                inherit: i32,
                options: u32,
            ) -> i32;
            fn GetCurrentProcess() -> *mut core::ffi::c_void;
        }
        let proc = unsafe { GetCurrentProcess() };
        let mut real_handle: *mut core::ffi::c_void = core::ptr::null_mut();
        unsafe {
            DuplicateHandle(
                proc,
                GetCurrentThread(),
                proc,
                &raw mut real_handle,
                0,
                0,
                2,
            );
        }
        let handle_val = real_handle as usize;
        Some(std::thread::spawn(move || {
            let thread_handle = handle_val as *mut core::ffi::c_void;
            std::thread::sleep(std::time::Duration::from_secs(2));
            // Sample RIP 5 times at 200ms intervals
            for sample in 0..5 {
                unsafe {
                    SuspendThread(thread_handle);
                    let mut ctx_buf = vec![0u8; 1232];
                    let flags: u32 = 0x10_0001; // CONTEXT_CONTROL
                    ctx_buf[48..52].copy_from_slice(&flags.to_le_bytes());
                    GetThreadContext(thread_handle, ctx_buf.as_mut_ptr());
                    let rip = u64::from_le_bytes(ctx_buf[248..256].try_into().unwrap());
                    let rsp = u64::from_le_bytes(ctx_buf[152..160].try_into().unwrap());

                    // Read 16 bytes at RIP
                    let code_bytes: [u8; 16] = {
                        let mut buf = [0u8; 16];
                        let src = rip as *const u8;
                        for (i, byte) in buf.iter_mut().enumerate() {
                            *byte = *src.add(i);
                        }
                        buf
                    };
                    let hex: String = code_bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    eprintln!("[watchdog #{sample}] RIP=0x{rip:X} RSP=0x{rsp:X} code=[{hex}]");

                    // If RIP is a JMP [RIP+disp32], read the IAT target
                    if code_bytes[0] == 0x48 && code_bytes[1] == 0xFF && code_bytes[2] == 0x25 {
                        let disp = i32::from_le_bytes(code_bytes[3..7].try_into().unwrap());
                        let iat_addr = (rip as i64 + 7 + i64::from(disp)) as u64;
                        let iat_val = *(iat_addr as *const u64);
                        eprintln!("[watchdog #{sample}]   IAT at 0x{iat_addr:X} -> 0x{iat_val:X}");
                        // Read first 32 bytes at target
                        let mut tgt_bytes = [0u8; 32];
                        for (i, byte) in tgt_bytes.iter_mut().enumerate() {
                            *byte = *((iat_val as *const u8).add(i));
                        }
                        let thex: String = tgt_bytes
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        eprintln!("[watchdog #{sample}]   target code=[{thex}]");
                    }

                    // Read top 8 stack entries
                    let rsp_val = rsp;
                    let mut stack_hex = String::new();
                    for i in 0..8 {
                        let addr = rsp_val + i * 8;
                        let val = *(addr as *const u64);
                        use core::fmt::Write as _;
                        let _ = write!(stack_hex, " 0x{val:X}");
                    }
                    eprintln!("[watchdog #{sample}]   stack:{stack_hex}");

                    ResumeThread(thread_handle);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            eprintln!("[watchdog] Done sampling");
        }))
    } else {
        None
    };

    unsafe {
        litebox_platform_windows_userland::run_thread_ref(&shim, &mut ctx);
    }

    // Signal network worker to stop and wait for it.
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    // Also mark the IPC transport dead so any in-progress send loop exits.
    if platform.has_network() {
        platform.poison_ipc();
    }
    if let Some(handle) = network_thread {
        let _ = handle.join();
    }

    let exit_code = shim.exit_code();
    std::process::exit(exit_code)
}

/// Build a minimal hello-world PE EXE that writes "Hello from NT shim!\n"
/// to stdout via kernel32!WriteConsoleA and exits via kernel32!ExitProcess.
fn build_hello_world_exe() -> Vec<u8> {
    // We need to call:
    //   HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);     // -11 = 0xFFFFFFF5
    //   WriteConsoleA(h, "Hello from NT shim!\n", 20, NULL, NULL);
    //   ExitProcess(0);
    //
    // The IAT slots will be at known RVAs. We'll embed the string in .text
    // after the code, then reference it via RIP-relative addressing.
    //
    // Layout of .text:
    //   0x00: code
    //   after code: "Hello from NT shim!\n" (20 bytes)

    let message = b"Hello from NT shim!\n";
    let msg_len = message.len();

    // We build code that uses absolute calls through the IAT.
    // IAT layout (from build_test_exe, .idata at RVA 0x2000):
    //   kernel32.dll: GetStdHandle(iat_rvas[0][0]), WriteConsoleA(iat_rvas[0][1]),
    //                 ExitProcess(iat_rvas[0][2])
    //
    // Since we don't know the exact IAT RVAs yet, we'll build in two passes:
    // First call build_test_exe with placeholder code, get IAT RVAs, then rebuild.

    let imports = vec![ImportDescriptor {
        dll_name: String::from("kernel32.dll"),
        functions: vec![
            ImportFunction {
                name: String::from("GetStdHandle"),
            },
            ImportFunction {
                name: String::from("WriteConsoleA"),
            },
            ImportFunction {
                name: String::from("ExitProcess"),
            },
        ],
    }];

    // First pass: build with dummy code to learn IAT RVAs
    let dummy_code = vec![0xCC; 128]; // placeholder
    let (_, iat_rvas) = build_test_exe(&dummy_code, &imports, DEFAULT_EXE_IMAGE_BASE);

    // IAT slot RVAs (these are stable because layout is deterministic)
    let get_std_handle_iat_rva = iat_rvas[0][0]; // kernel32!GetStdHandle
    let write_console_a_iat_rva = iat_rvas[0][1]; // kernel32!WriteConsoleA
    let exit_process_iat_rva = iat_rvas[0][2]; // kernel32!ExitProcess

    // Build the actual code using the IAT RVAs.
    // The code starts at RVA 0x1000 (.text section).
    // We'll embed the message string right after the code.
    let mut code = Vec::new();

    // sub rsp, 0x38   (shadow space + alignment: 0x20 shadow + 0x10 for 5th arg + 8 alignment)
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);

    // --- GetStdHandle(STD_OUTPUT_HANDLE) ---
    // mov ecx, 0xFFFFFFF5  (STD_OUTPUT_HANDLE = -11)
    code.extend_from_slice(&[0xB9, 0xF5, 0xFF, 0xFF, 0xFF]);
    // call qword ptr [rip + offset_to_GetStdHandle_IAT]
    // The call is at code offset = current len, the next instruction is at current len + 6
    // Target is image_base + get_std_handle_iat_rva
    // RIP-relative offset = target_rva - (code_rva + instruction_len)
    let call1_offset = code.len();
    code.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]); // placeholder

    // --- WriteConsoleA(rax, msg_ptr, msg_len, NULL, NULL) ---
    // mov rcx, rax           (hConsoleOutput = return value of GetStdHandle)
    code.extend_from_slice(&[0x48, 0x89, 0xC1]);
    // lea rdx, [rip + offset_to_message]
    let lea_offset = code.len();
    code.extend_from_slice(&[0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00]); // placeholder
    // mov r8d, msg_len
    code.push(0x41);
    code.push(0xB8);
    code.extend_from_slice(&(msg_len as u32).to_le_bytes());
    // xor r9, r9             (lpNumberOfCharsWritten = NULL)
    code.extend_from_slice(&[0x4D, 0x31, 0xC9]);
    // mov qword ptr [rsp+0x20], 0  (lpReserved = NULL, 5th param on stack)
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00]);
    // call qword ptr [rip + offset_to_WriteConsoleA_IAT]
    let call2_offset = code.len();
    code.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]); // placeholder

    // --- ExitProcess(0) ---
    // xor ecx, ecx
    code.extend_from_slice(&[0x31, 0xC9]);
    // call qword ptr [rip + offset_to_ExitProcess_IAT]
    let call3_offset = code.len();
    code.extend_from_slice(&[0xFF, 0x15, 0x00, 0x00, 0x00, 0x00]); // placeholder

    // int3 (should never reach here)
    code.push(0xCC);

    // Embed the message string right after the code.
    let msg_code_offset = code.len();
    code.extend_from_slice(message);

    // Now patch the RIP-relative offsets.
    // All offsets are relative to the end of the instruction containing the offset.
    let text_rva: u32 = 0x1000;

    // Patch call1: call [rip + X] where X = IAT_RVA - (text_rva + call1_offset + 6)
    let call1_rip = text_rva + (call1_offset as u32) + 6;
    let call1_rel = (i64::from(get_std_handle_iat_rva) - i64::from(call1_rip)) as i32;
    code[call1_offset + 2..call1_offset + 6].copy_from_slice(&call1_rel.to_le_bytes());

    // Patch lea: lea rdx, [rip + X] where X = msg_rva - (text_rva + lea_offset + 7)
    let msg_rva = text_rva + msg_code_offset as u32;
    let lea_rip = text_rva + (lea_offset as u32) + 7;
    let lea_rel = (i64::from(msg_rva) - i64::from(lea_rip)) as i32;
    code[lea_offset + 3..lea_offset + 7].copy_from_slice(&lea_rel.to_le_bytes());

    // Patch call2: call [rip + X]
    let call2_rip = text_rva + (call2_offset as u32) + 6;
    let call2_rel = (i64::from(write_console_a_iat_rva) - i64::from(call2_rip)) as i32;
    code[call2_offset + 2..call2_offset + 6].copy_from_slice(&call2_rel.to_le_bytes());

    // Patch call3: call [rip + X]
    let call3_rip = text_rva + (call3_offset as u32) + 6;
    let call3_rel = (i64::from(exit_process_iat_rva) - i64::from(call3_rip)) as i32;
    code[call3_offset + 2..call3_offset + 6].copy_from_slice(&call3_rel.to_le_bytes());

    // Second pass: build for real with the actual code
    let (exe_bytes, _) = build_test_exe(&code, &imports, DEFAULT_EXE_IMAGE_BASE);
    exe_bytes
}

/// Adapter implementing [`PeMemoryMapper`] using the litebox PageManager.
/// Used for the stub-DLL path and other allocations tracked by PageManager.
struct PageManagerMapper<'a> {
    pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
}

/// PM-backed mapper for real DLL loading.
///
/// Uses the PageManager for all memory operations, mirroring how the
/// Linux runner routes ELF segment loading through `sys_mmap()` → platform.
/// This ensures the PM tracks every page, so `NtQueryVirtualMemory`,
/// `NtProtectVirtualMemory`, etc. work correctly for DLL and EXE regions.
///
/// Call `pre_reserve()` to allocate the full image range as writable
/// pages through the PM, then `map_section()` copies data and adjusts
/// per-section permissions.
struct PmMapper<'a> {
    pub(crate) pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
}

impl<'a> PmMapper<'a> {
    fn new(pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>) -> Self {
        Self { pm }
    }

    /// Reserve the full PE image range as writable pages via the PageManager.
    fn pre_reserve(&self, base: usize, size: usize) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        eprintln!("[pm-mapper] pre_reserve(0x{base:X}, 0x{aligned:X})");
        let addr = NonZeroAddress::<PAGE_SIZE>::new(base).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(aligned).ok_or(PeLoadError::MapFailed)?;
        let flags = CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;
        // Allocate as writable so map_section() can copy data into each section.
        unsafe {
            self.pm
                .create_writable_pages(Some(addr), page_size, flags, |_| Ok(0))
        }
        .map_err(|e| {
            eprintln!("[pm-mapper] pre_reserve FAILED: {e:?}");
            PeLoadError::MapFailed
        })?;
        Ok(())
    }
}

impl PeMemoryMapper for PmMapper<'_> {
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), PeLoadError> {
        let aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        eprintln!(
            "[pm-mapper] map_section(0x{va:X}, data_len={}, size=0x{size:X}/{aligned:X}, perm={perm:?})",
            data.len()
        );

        // Pages are already committed-writable from pre_reserve().
        // Copy section data.
        if !data.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), va as *mut u8, data.len());
            }
        }

        // Adjust protection to match the section's intended permissions.
        let ptr =
            <Platform as litebox::platform::RawPointerProvider>::RawMutPointer::from_usize(va);
        match perm {
            SectionPermissions::ReadExecute => unsafe {
                self.pm.make_pages_executable(ptr, aligned)
            },
            SectionPermissions::ReadOnly => unsafe { self.pm.make_pages_readable(ptr, aligned) },
            SectionPermissions::ReadWrite => {
                // Already writable from pre_reserve — nothing to do.
                Ok(())
            }
        }
        .map_err(|e| {
            eprintln!("[pm-mapper] permission change FAILED: {e:?}");
            PeLoadError::MapFailed
        })?;

        Ok(())
    }
}

impl PeMemoryMapper for PageManagerMapper<'_> {
    fn map_section(
        &mut self,
        va: usize,
        data: &[u8],
        size: usize,
        perm: SectionPermissions,
    ) -> Result<(), PeLoadError> {
        let addr = NonZeroAddress::<PAGE_SIZE>::new(va).ok_or(PeLoadError::MapFailed)?;
        let page_size = NonZeroPageSize::<PAGE_SIZE>::new(size).ok_or(PeLoadError::MapFailed)?;
        let flags = CreatePagesFlags::FIXED_ADDR | CreatePagesFlags::POPULATE_PAGES_IMMEDIATELY;

        // Capture data in an owned copy since the closure may outlive the borrow.
        let data_owned: Vec<u8> = data.to_vec();

        let map_fn =
            |ptr: <Platform as litebox::platform::RawPointerProvider>::RawMutPointer<u8>| {
                if !data_owned.is_empty() {
                    ptr.copy_from_slice(0, &data_owned)
                        .ok_or(litebox::mm::linux::MappingError::OutOfMemory)?;
                }
                Ok(data_owned.len())
            };

        // If the VA falls within a pre-reserved region, we need to write data
        // directly (the PageManager already owns the VMA). We use Replace to
        // split the existing VMA and change permissions for this sub-range.
        let result = match perm {
            SectionPermissions::ReadExecute => unsafe {
                self.pm
                    .create_executable_pages(Some(addr), page_size, flags, map_fn)
            },
            SectionPermissions::ReadWrite => unsafe {
                self.pm
                    .create_writable_pages(Some(addr), page_size, flags, map_fn)
            },
            SectionPermissions::ReadOnly => unsafe {
                self.pm
                    .create_readable_pages(Some(addr), page_size, flags, map_fn)
            },
        };

        if let Err(ref e) = result {
            eprintln!(
                "[mapper] FAILED map_section va=0x{va:X} size=0x{size:X} data_len={} perm={perm:?} err={e:?}",
                data.len()
            );
        }

        result.map(|_| ()).map_err(|_| PeLoadError::MapFailed)
    }
}

/// Write IAT patches to guest memory.
///
/// On Windows userland, guest and host share the same address space. The IAT
/// section is often in .rdata (mapped ReadOnly), so we need VirtualProtect to
/// temporarily make it writable.
fn apply_iat_patches(_pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>, patches: &[IatPatch]) {
    for patch in patches {
        unsafe {
            let ptr = patch.iat_va as *mut u64;
            // Make the page writable.
            let mut old_protect: u32 = 0;
            VirtualProtect(
                ptr.cast::<u8>(),
                8,
                0x04, /* PAGE_READWRITE */
                &raw mut old_protect,
            );
            core::ptr::write(ptr, patch.resolved_va);
            // Restore original protection.
            let mut dummy: u32 = 0;
            VirtualProtect(ptr.cast::<u8>(), 8, old_protect, &raw mut dummy);
        }
    }
}

// ---------------------------------------------------------------------------
// Broker IPC helpers
// ---------------------------------------------------------------------------

/// IPC handshake constants (must match `litebox_broker` protocol).
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";
const HANDSHAKE_VERSION: u16 = 1;
const HANDSHAKE_MTU: u16 = 1600;

/// Connect to the network broker via TCP loopback and perform the LBNP
/// handshake. Returns a **non-blocking** `TcpStream` ready for the
/// platform's `IPInterfaceProvider` to use.
fn connect_to_broker_ipc(addr: &str) -> Result<std::net::TcpStream> {
    use std::io::{Read, Write};

    let sock_addr: std::net::SocketAddr = addr
        .parse()
        .map_err(|e| anyhow!("Invalid broker address '{addr}': {e}"))?;

    // Security: only allow loopback addresses for the IPC control plane.
    let ip = sock_addr.ip();
    if !ip.is_loopback() {
        anyhow::bail!(
            "Broker address '{addr}' is not a loopback address. \
             Only 127.0.0.1 or [::1] are allowed for security."
        );
    }

    // Blocking connect — we don't have anything else to do yet.
    let mut stream =
        std::net::TcpStream::connect_timeout(&sock_addr, std::time::Duration::from_secs(5))
            .map_err(|e| anyhow!("Failed to connect to broker at {addr}: {e}"))?;

    stream.set_nodelay(true).ok(); // reduce latency for small IPC frames

    // --- Send handshake: magic (4) + version (2) + MTU (2) = 8 bytes ---
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    msg[6..8].copy_from_slice(&HANDSHAKE_MTU.to_le_bytes());
    stream
        .write_all(&msg)
        .map_err(|e| anyhow!("IPC handshake send failed: {e}"))?;

    // --- Read response (8 bytes, with timeout) ---
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .ok();
    let mut resp = [0u8; 8];
    stream
        .read_exact(&mut resp)
        .map_err(|e| anyhow!("IPC handshake response failed: {e}"))?;

    // Validate response.
    if &resp[0..4] != HANDSHAKE_MAGIC {
        anyhow::bail!("IPC handshake: bad magic in response");
    }
    let version = u16::from_le_bytes([resp[4], resp[5]]);
    if version != HANDSHAKE_VERSION {
        anyhow::bail!(
            "IPC handshake: version mismatch (got {version}, expected {HANDSHAKE_VERSION})"
        );
    }
    let mtu = u16::from_le_bytes([resp[6], resp[7]]);
    if mtu != HANDSHAKE_MTU {
        anyhow::bail!("IPC handshake: MTU mismatch (broker sent {mtu}, we expect {HANDSHAKE_MTU})");
    }
    if cfg!(debug_assertions) {
        eprintln!("IPC handshake complete: broker MTU={mtu}");
    }

    // Switch to non-blocking for the platform's poll-based I/O loop.
    stream
        .set_nonblocking(true)
        .map_err(|e| anyhow!("Failed to set non-blocking on IPC stream: {e}"))?;
    stream.set_read_timeout(None).ok();

    Ok(stream)
}

/// Start the network worker thread if a network stack is configured.
///
/// The thread repeatedly calls `perform_platform_interaction()` on the smoltcp
/// `Network`, then waits on the platform transport until data arrives or a
/// timeout fires. This mirrors the Linux runner's network worker pattern.
fn start_network_worker(
    net: Option<&Arc<std::sync::Mutex<litebox::net::Network<Platform>>>>,
    shutdown: &Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    let net = net?.clone();
    let shutdown = shutdown.clone();

    let handle = std::thread::Builder::new()
        .name("network-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_micros(100);

            while !shutdown.load(core::sync::atomic::Ordering::Relaxed) {
                let timeout = loop {
                    match net.lock().unwrap().perform_platform_interaction() {
                        litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                        litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                            break timeout;
                        }
                    }
                };
                let wait = match timeout {
                    Some(t) if t < DEFAULT_TIMEOUT => t,
                    _ => DEFAULT_TIMEOUT,
                };
                litebox_platform_multiplex::platform().wait_on_network(Some(wait));
            }
            // Drain remaining network interactions before exiting.
            while net
                .lock()
                .unwrap()
                .perform_platform_interaction()
                .call_again_immediately()
            {}
        })
        .expect("failed to spawn network worker thread");

    Some(handle)
}
