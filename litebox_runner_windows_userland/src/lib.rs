// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows userland PE runner for LiteBox.
//!
//! Loads a PE executable into a LiteBox address space using the NT shim,
//! generates stub DLLs (ntdll.dll, kernel32.dll), resolves imports,
//! synthesizes PEB/TEB, and runs the guest until it terminates.
//!
//! ## Usage
//!
//! ```text
//! litebox_runner_windows_userland --pe-file hello.exe
//! ```
//!
//! For Phase 1, only static PE executables that import from ntdll.dll and
//! kernel32.dll are supported. The guest uses `syscall` to communicate with
//! the NT shim.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]
#![allow(
    // PE format code inherently involves cross-width casts and integer wrapping.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
)]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use std::path::PathBuf;

use litebox::mm::linux::{CreatePagesFlags, NonZeroAddress, NonZeroPageSize};
use litebox::platform::{AddressSpaceProvider, RawConstPointer, RawMutPointer, SystemInfoProvider};
use litebox_common_windows::pe_builder::{ImportDescriptor, ImportFunction, build_test_exe};
use litebox_common_windows::pe_loader::{
    IatPatch, LoadedModule, PeLoadError, PeMemoryMapper, SectionPermissions, load_pe,
    resolve_imports,
};
use litebox_common_windows::pe_parser::PeParsedFile;
use litebox_common_windows::stub_dlls;
use litebox_platform_multiplex::Platform;
use litebox_shim_windows::peb_teb::{PebTebLayout, PebTebParams, build_peb_teb_bytes};

/// Page size for the Windows userland platform.
const PAGE_SIZE: usize = 4096;

/// Default image base for test EXEs when none is specified.
const DEFAULT_EXE_IMAGE_BASE: u64 = 0x0000_0040_0000;

/// Stack size: 1 MiB (matching Windows default).
const GUEST_STACK_SIZE: usize = 0x0010_0000;

/// Stub DLL base addresses — within the VA partition (slot 0 = 0..1TiB).
/// Place them at high-but-within-partition addresses to avoid conflicts with
/// the EXE (at 0x40_0000) and heap. 0xF0_0000_0000 is ~960 GiB into the
/// 1 TiB partition, leaving plenty of space.
const NTDLL_LOAD_BASE: usize = 0xF0_0000_0000;
const KERNEL32_LOAD_BASE: usize = 0xF0_0001_0000;
const ADVAPI32_LOAD_BASE: usize = 0xF0_0002_0000;

/// PEB/TEB region base — placed just below the stub DLLs.
const PEB_TEB_BASE: usize = 0xEF_FFFF_0000;

/// Run Windows PE programs with LiteBox.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// Path to the PE executable to run.
    #[arg(long = "pe-file", value_name = "PATH", value_hint = clap::ValueHint::FilePath)]
    pub pe_file: Option<PathBuf>,
    /// Run the built-in hello world test instead of a file.
    #[arg(long = "test-hello")]
    pub test_hello: bool,
}

/// Run a Windows PE program with LiteBox.
///
/// # Panics
///
/// Panics if the platform cannot allocate page-aligned memory for the guest
/// stack, PEB/TEB, or PE sections. These are programming errors rather than
/// user-recoverable conditions.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let pe_data = if cli_args.test_hello {
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
    let litebox = litebox::LiteBox::new(platform);

    // Allocate guest address space.
    let as_id = platform
        .create_address_space()
        .map_err(|e| anyhow!("Failed to allocate address space: {e:?}"))?;
    let as_range = platform
        .address_space_range(as_id)
        .map_err(|e| anyhow!("Failed to get address space range: {e:?}"))?;
    let guest_va_start = as_range.start;
    let guest_va_end = as_range.end;

    let pm = litebox::mm::PageManager::new(&litebox, as_range);

    // Create the process state that will be shared with the shim.
    // The runner uses pm via process_state.pm for all mapping operations.
    let process_state = alloc::sync::Arc::new(litebox_shim_windows::NtProcessState::new(pm));

    // Build and map stub DLLs.
    // Use the actual load base so preferred == actual → no rebase → .text stays RX.
    let syscall_entry = platform.get_syscall_entry_point() as u64;
    let gs_table_ptr = platform.guest_gs_table_ptr() as u64;
    let ntdll_bytes =
        stub_dlls::build_ntdll_for(NTDLL_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
    let kernel32_bytes =
        stub_dlls::build_kernel32_for(KERNEL32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);
    let advapi32_bytes =
        stub_dlls::build_advapi32_for(ADVAPI32_LOAD_BASE as u64, syscall_entry, gs_table_ptr);

    let ntdll_parsed = PeParsedFile::parse(&ntdll_bytes)
        .map_err(|e| anyhow!("Failed to parse ntdll stub: {e}"))?;
    let kernel32_parsed = PeParsedFile::parse(&kernel32_bytes)
        .map_err(|e| anyhow!("Failed to parse kernel32 stub: {e}"))?;
    let advapi32_parsed = PeParsedFile::parse(&advapi32_bytes)
        .map_err(|e| anyhow!("Failed to parse advapi32 stub: {e}"))?;

    let mut mapper = PageManagerMapper {
        pm: &process_state.pm,
    };

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

    if cfg!(debug_assertions) {
        eprintln!(
            "ntdll loaded at 0x{:X}, kernel32 at 0x{:X}, advapi32 at 0x{:X}",
            ntdll_info.image_base, kernel32_info.image_base, advapi32_info.image_base
        );
    }

    // Parse and load the main EXE.
    let exe_parsed =
        PeParsedFile::parse(&pe_data).map_err(|e| anyhow!("Failed to parse PE executable: {e}"))?;

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
                "Rebasing EXE from 0x{:X} to 0x{:X} (outside guest VA 0x{:X}..0x{:X})",
                preferred_base, base, guest_va_start, guest_va_end
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
    ];

    eprintln!("resolving imports...");
    let patches = resolve_imports(&exe_parsed, &pe_data, exe_base, &modules)
        .map_err(|e| anyhow!("Failed to resolve imports: {e}"))?;

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
    let (stdin_h, stdout_h, stderr_h) = shim.stdio_handles();

    let peb_teb_layout = PebTebLayout::at_base(PEB_TEB_BASE);
    let peb_teb_params = PebTebParams {
        stack_base: stack_alloc_top,
        stack_limit: stack_base,
        image_base: exe_info.image_base,
        process_heap: 0, // Phase 2 will provide a real heap
        command_line_wide: "hello.exe".encode_utf16().collect(),
        stdin_handle: u64::from(stdin_h),
        stdout_handle: u64::from(stdout_h),
        stderr_handle: u64::from(stderr_h),
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
    }

    // Derive the EXE module name for GetModuleHandleW lookups.
    let exe_full_path = if let Some(pe_path) = &cli_args.pe_file {
        pe_path
            .canonicalize()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| pe_path.to_str().unwrap_or("C:\\app.exe").to_string())
    } else {
        String::from("C:\\hello.exe")
    };

    let exe_module_name = if let Some(pe_path) = &cli_args.pe_file {
        pe_path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("unknown.exe")
            .to_string()
    } else {
        // --test-hello built-in EXE
        String::from("hello.exe")
    };

    // Set up initial thread state.
    shim.set_init_state(litebox_shim_windows::NtInitState {
        entry_point: exe_info.entry_point,
        stack_top,
        teb_va: peb_teb_layout.teb_va,
        peb_va: peb_teb_layout.peb_va,
        image_base: exe_info.image_base,
        process_params_va: peb_teb_layout.process_params_va,
        cmdline_ansi_va: peb_teb_layout.cmdline_ansi_buffer_va,
        env_block_va: peb_teb_layout.env_block_va,
        module_bases: vec![
            litebox_shim_windows::ModuleBase {
                name: exe_module_name,
                path: exe_full_path.clone(),
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
        ],
        guest_va_start,
        guest_va_end,
        exe_path: exe_full_path,
    });

    // Run the guest.
    // Tell the platform to set GS = guest TEB before entering guest code.
    litebox_platform_windows_userland::WindowsUserland::set_guest_gs_base(
        peb_teb_layout.teb_va as u64,
    );
    let mut ctx = litebox_common_linux::ExecutionContext::default();
    unsafe {
        litebox_platform_windows_userland::run_thread_ref(&shim, &mut ctx);
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
struct PageManagerMapper<'a> {
    pm: &'a litebox::mm::PageManager<Platform, PAGE_SIZE>,
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

        result.map(|_| ()).map_err(|_| PeLoadError::MapFailed)
    }
}

/// Write IAT patches to guest memory.
///
/// On Windows userland, guest and host share the same address space. The IAT
/// section is often in .rdata (mapped ReadOnly), so we need VirtualProtect to
/// temporarily make it writable.
fn apply_iat_patches(_pm: &litebox::mm::PageManager<Platform, PAGE_SIZE>, patches: &[IatPatch]) {
    unsafe extern "system" {
        fn VirtualProtect(
            lpAddress: *mut u8,
            dwSize: usize,
            flNewProtect: u32,
            lpflOldProtect: *mut u32,
        ) -> i32;
    }

    for patch in patches {
        unsafe {
            let ptr = patch.iat_va as *mut u64;
            // Make the page writable.
            let mut old_protect: u32 = 0;
            VirtualProtect(
                ptr as *mut u8,
                8,
                0x04, /* PAGE_READWRITE */
                &mut old_protect,
            );
            core::ptr::write(ptr, patch.resolved_va);
            // Restore original protection.
            let mut dummy: u32 = 0;
            VirtualProtect(ptr as *mut u8, 8, old_protect, &mut dummy);
        }
    }
}
