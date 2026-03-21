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
use litebox_common_windows::pe_loader::{PeLoadError, PeMemoryMapper, SectionPermissions, load_pe};
use litebox_common_windows::pe_parser::PeParsedFile;
use litebox_platform_multiplex::Platform;
use litebox_shim_windows::peb_teb::{PebTebLayout, PebTebParams, build_peb_teb_bytes};

/// Page size for the Windows userland platform.
const PAGE_SIZE: usize = 4096;

/// Stack size: 1 MiB (matching Windows default).
const GUEST_STACK_SIZE: usize = 0x0010_0000;

/// PEB/TEB region offset — placed well below the DLL region.
const PEB_TEB_OFFSET: usize = 0x7E_FFF0_0000;

/// Run Windows PE programs with LiteBox.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// Path to the PE executable to run. If omitted and --dll-tar contains
    /// an .exe, that EXE is used automatically.
    #[arg(long = "pe-file", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub pe_file: Option<PathBuf>,
    /// Connect to a network broker via TCP loopback at the given address
    /// (e.g., "127.0.0.1:9000"). The broker must be listening and speaking
    /// the litebox IPC network protocol (LBNP handshake).
    #[arg(long = "network-broker", value_name = "ADDR")]
    pub network_broker: Option<String>,
    /// Path to a tar file containing real DLLs (ntdll.dll, kernel32.dll,
    /// etc.) and optionally the main EXE.
    #[arg(long = "dll-tar", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub dll_tar: PathBuf,
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
    // The EXE can come from --pe-file, or we look for it inside the tar.
    let pe_data = if let Some(pe_path) = &cli_args.pe_file {
        std::fs::read(pe_path)
            .map_err(|e| anyhow!("Could not read PE file at {}: {}", pe_path.display(), e))?
    } else {
        // Will extract from tar VFS below.
        Vec::new()
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
        Some(Arc::new(spin::Mutex::new(n)))
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

    #[allow(non_snake_case)]
    let PEB_TEB_BASE = guest_va_start + PEB_TEB_OFFSET;

    let pm = litebox::mm::PageManager::new(&litebox, as_range);

    // Create the process state that will be shared with the shim.
    // The runner uses pm via process_state.pm for all mapping operations.
    let process_state = alloc::sync::Arc::new(litebox_shim_windows::NtProcessState::new(pm));

    // ── Loading path ────────────────────────────────────────────────
    // Load real DLLs (ntdll with rewritten syscalls) and the EXE from
    // the tar-backed VFS. ntdll's LdrpInitialize loads all other DLLs
    // via syscalls that the shim intercepts and serves from VFS.
    struct LoadResult {
        exe_entry_point: usize,
        exe_image_base: usize,
        exe_image_size: usize,
        module_bases: Vec<litebox_shim_windows::ModuleBase>,
        /// VA of LdrInitializeThunk (thread entry point).
        ldr_init_thunk_va: usize,
        /// VA of RtlUserThreadStart (CONTEXT.Rip after init).
        rtl_user_thread_start_va: usize,
        /// Layered VFS for the shim (created early so boot can read from it).
        vfs: alloc::sync::Arc<litebox_shim_windows::NtFS>,
        /// Mapping from real Windows syscall numbers to NtSyscallId.
        syscall_map: litebox_common_windows::NtSyscallMap,
        /// Unhandled stub names for debug logging of unknown syscalls.
        unhandled_stubs: Vec<(u32, String)>,
        /// RVA of KiUserExceptionDispatcher in ntdll for SEH dispatch.
        ki_user_exception_dispatcher_rva: Option<usize>,
    }

    let load_result = {
        // ── ntdll-driven init path ────────────────────────────────
        // Load only ntdll (with rewritten syscalls) and the EXE.
        // ntdll's LdrpInitialize will load all other DLLs via syscalls
        // that we intercept and serve from the tar file.
        let tar_data = std::fs::read(&cli_args.dll_tar).map_err(|e| {
            anyhow!(
                "Could not read DLL tar at {}: {e}",
                cli_args.dll_tar.display()
            )
        })?;
        #[allow(clippy::cast_precision_loss)]
        let tar_size_mb = tar_data.len() as f64 / 1_048_576.0;
        eprintln!(
            "[real-dlls] Read tar: {} ({tar_size_mb:.1} MB)",
            cli_args.dll_tar.display(),
        );
        // Create layered VFS early so both boot loading and the shim share it.
        // Architecture: InMemFS (writable) → DeviceFS → TarFS (read-only).
        let vfs_arc = {
            use litebox::fs::FileSystem as _;

            let mut in_mem = litebox::fs::in_mem::FileSystem::new(&litebox);
            in_mem.with_root_privileges(|fs| {
                fs.mkdir(
                    "/c",
                    litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
                )
                .ok();
                fs.mkdir(
                    "/c/app",
                    litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
                )
                .ok();
            });

            let dev_fs = litebox::fs::devices::FileSystem::new(&litebox);
            let tar_fs =
                litebox::fs::tar_ro::FileSystem::new(&litebox, alloc::borrow::Cow::Owned(tar_data));

            let inner = litebox::fs::layered::FileSystem::new(
                &litebox,
                dev_fs,
                tar_fs,
                litebox::fs::layered::LayeringSemantics::LowerLayerReadOnly,
            );
            let vfs = litebox::fs::layered::FileSystem::new(
                &litebox,
                in_mem,
                inner,
                litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
            );
            alloc::sync::Arc::new(vfs)
        };
        eprintln!("[vfs] Layered VFS created (InMemFS → DeviceFS → TarFS)");

        // Log VFS root entries for debugging.
        {
            use litebox::fs::FileSystem as _;
            if let Ok(fd) = vfs_arc.open(
                "/",
                litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                litebox::fs::Mode::RUSR,
            ) {
                if let Ok(entries) = vfs_arc.read_dir(&fd) {
                    eprintln!("[vfs] Root entries: {}", entries.len());
                    for e in &entries {
                        eprintln!("  /{}: {:?}", e.name, e.file_type);
                    }
                }
                let _ = vfs_arc.close(&fd);
            }
        }

        // If no --pe-file, look for an EXE inside the VFS.
        let pe_data = if pe_data.is_empty() {
            let exe_path = real_dlls::find_vfs_file_by_name(&vfs_arc, ".exe")
                .or_else(|| {
                    // Search more broadly: list root and find any .exe file.
                    use litebox::fs::FileSystem as _;
                    let fd = vfs_arc
                        .open(
                            "/",
                            litebox::fs::OFlags::RDONLY | litebox::fs::OFlags::DIRECTORY,
                            litebox::fs::Mode::RUSR,
                        )
                        .ok()?;
                    let entries = vfs_arc.read_dir(&fd).ok()?;
                    let _ = vfs_arc.close(&fd);
                    entries.iter().find_map(|e| {
                        if e.name.len() >= 4
                            && e.name[e.name.len() - 4..].eq_ignore_ascii_case(".exe")
                        {
                            Some(format!("/{}", e.name))
                        } else {
                            None
                        }
                    })
                })
                .ok_or_else(|| anyhow!("No --pe-file and no .exe found in VFS"))?;
            eprintln!("[real-dlls] Using {exe_path} from VFS");
            real_dlls::read_vfs_file(&vfs_arc, &exe_path)?
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
        let result = real_dlls::load_ntdll_for_init(&vfs_arc, &mut pm_mapper, guest_va_start)?;

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
            ldr_init_thunk_va: result.ldr_init_thunk_va,
            rtl_user_thread_start_va: result.rtl_user_thread_start_va,
            vfs: vfs_arc,
            syscall_map: result.syscall_map,
            unhandled_stubs: result.unhandled_stubs,
            ki_user_exception_dispatcher_rva: result.ki_user_exception_dispatcher_rva,
        }
    };

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
    shim.set_syscall_map(load_result.syscall_map);
    if !load_result.unhandled_stubs.is_empty() {
        shim.set_unhandled_stubs(load_result.unhandled_stubs);
    }
    let (stdin_h, stdout_h, stderr_h) = shim.stdio_handles();

    let peb_teb_layout = PebTebLayout::at_base(PEB_TEB_BASE);

    // ntdll's RtlAllocateHeap needs a real Windows heap.
    let process_heap = {
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

    // Build a CONTEXT on the guest stack and set the entry point to
    // LdrInitializeThunk. ntdll's loader will initialize the process and
    // then NtContinue to the real entry point (RtlUserThreadStart).
    let ldr_init_va = load_result.ldr_init_thunk_va;
    let rtl_uts_va = load_result.rtl_user_thread_start_va;
    let (effective_entry_point, effective_stack_top, context_ptr_arg, ntdll_base_arg) = {
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

        (ldr_init_va, ldr_rsp, context_va, ntdll_base)
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
        ki_user_exception_dispatcher_rva: load_result.ki_user_exception_dispatcher_rva,
    });

    // Capture NLS data from host and pass to shim (so shim doesn't call host APIs).
    if let Some(nls) = capture_host_nls_data() {
        shim.set_nls_data(nls);
    }

    // Pass the pre-built VFS to the shim for file I/O.
    shim.set_fs(load_result.vfs);

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
    let _watchdog = {
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
    net: Option<&Arc<spin::Mutex<litebox::net::Network<Platform>>>>,
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
                    match net.lock().perform_platform_interaction() {
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
                .perform_platform_interaction()
                .call_again_immediately()
            {}
        })
        .expect("failed to spawn network worker thread");

    Some(handle)
}

/// Capture NLS data from the host's real ntdll so the shim doesn't need to
/// call host APIs (GetModuleHandleA, GetProcAddress, VirtualQuery) at runtime.
fn capture_host_nls_data() -> Option<litebox_shim_windows::NlsData> {
    type NtInitNlsFn = unsafe extern "system" fn(*mut *mut u8, *mut u32, *mut i64) -> i32;

    unsafe extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut core::ffi::c_void;
        fn GetProcAddress(
            module: *mut core::ffi::c_void,
            name: *const u8,
        ) -> *mut core::ffi::c_void;
        fn VirtualQuery(addr: *const u8, info: *mut u8, len: usize) -> usize;
    }

    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return None;
        }
        let proc = GetProcAddress(ntdll, c"NtInitializeNlsFiles".as_ptr().cast());
        if proc.is_null() {
            return None;
        }
        let func: NtInitNlsFn = core::mem::transmute(proc);
        let mut base: *mut u8 = core::ptr::null_mut();
        let mut locale: u32 = 0;
        let mut casing: i64 = 0;
        let status = func(&mut base, &mut locale, &mut casing);
        if status != 0 || base.is_null() {
            return None;
        }
        // Query section size via VirtualQuery (MEMORY_BASIC_INFORMATION).
        #[repr(C)]
        struct Mbi {
            base_address: usize,
            alloc_base: usize,
            alloc_protect: u32,
            _pad0: u16,
            _pad1: u16,
            region_size: usize,
            state: u32,
            protect: u32,
            type_: u32,
            _pad2: u32,
        }
        let mut mbi = core::mem::zeroed::<Mbi>();
        let ret = VirtualQuery(base, (&raw mut mbi).cast(), core::mem::size_of::<Mbi>());
        let section_size = if ret != 0 { mbi.region_size } else { 0xD3000 };
        let section = core::slice::from_raw_parts(base, section_size).to_vec();
        Some(litebox_shim_windows::NlsData {
            section,
            locale_id: locale,
            casing_size: casing,
        })
    }
}
