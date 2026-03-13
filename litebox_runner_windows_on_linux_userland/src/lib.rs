// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner for Windows programs on Linux
//!
//! This crate provides the CLI interface for running Windows PE binaries
//! on Linux using LiteBox.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_linux_for_windows::LinuxPlatformForWindows;
use litebox_platform_linux_for_windows::register_dynamic_exports;
use litebox_platform_linux_for_windows::register_exception_table;
use litebox_platform_linux_for_windows::set_process_command_line;
use litebox_platform_linux_for_windows::set_sandbox_root;
use litebox_platform_linux_for_windows::set_volume_serial;
use litebox_shim_windows::loader::{ExecutionContext, PeLoader, call_entry_point};
use litebox_shim_windows::syscalls::ntdll::{NtdllApi, memory_protection};
use litebox_shim_windows::tracing::{
    ApiCategory, FilterRule, TraceConfig, TraceFilter, TraceFormat, TraceOutput, TracedNtdllApi,
    Tracer,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Run Windows programs with LiteBox on unmodified Linux
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The Windows program to run (PE executable)
    #[arg(required = true, value_hint = clap::ValueHint::FilePath)]
    pub program: String,

    /// Arguments to pass to the program
    #[arg(trailing_var_arg = true)]
    pub arguments: Vec<String>,

    /// Enable API call tracing
    #[arg(long = "trace-apis")]
    pub trace_apis: bool,

    /// Trace output format: text or json
    #[arg(long = "trace-format", default_value = "text")]
    pub trace_format: String,

    /// Trace output file (defaults to stdout)
    #[arg(long = "trace-output")]
    pub trace_output: Option<PathBuf>,

    /// Filter traces by function pattern (e.g., "Nt*File")
    #[arg(long = "trace-filter")]
    pub trace_filter: Option<String>,

    /// Filter traces by category (file_io, console_io, memory)
    #[arg(long = "trace-category")]
    pub trace_category: Option<String>,

    /// Restrict all file-path operations to this directory (sandbox root).
    /// Paths that would escape the root via `..` traversal are rejected.
    #[arg(long = "root", value_hint = clap::ValueHint::DirPath)]
    pub root: Option<String>,

    /// Volume serial number reported by GetFileInformationByHandle.
    /// Accepts decimal (e.g. 305419896) or hex with 0x prefix (e.g. 0x12345678).
    /// When omitted a value is generated randomly from the process ID and time.
    #[arg(long = "volume-serial", value_parser = parse_volume_serial)]
    pub volume_serial: Option<u32>,

    /// Show verbose PE loader diagnostic output.
    /// When not set, loader logs are suppressed and only the program's own output is shown.
    #[arg(long = "verbose")]
    pub verbose: bool,
}

/// Parse a u32 from either a decimal string or a `0x`-prefixed hex string.
fn parse_volume_serial(s: &str) -> Result<u32, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|e| format!("invalid hex value: {e}"))
    } else {
        s.parse::<u32>()
            .map_err(|e| format!("invalid decimal value: {e}"))
    }
}

/// Run Windows programs with LiteBox on unmodified Linux
pub fn run(cli_args: CliArgs) -> Result<()> {
    let verbose = cli_args.verbose;
    // Emit a PE-loader diagnostic line only when --verbose is set.
    macro_rules! loader_log {
        ($($arg:tt)*) => {
            if verbose {
                println!($($arg)*);
            }
        };
    }

    // Read the PE binary
    let pe_data = std::fs::read(&cli_args.program)?;

    // Load and parse the PE binary
    let pe_loader = PeLoader::new(pe_data).map_err(|e| anyhow!("Failed to load PE binary: {e}"))?;

    loader_log!("Loaded PE binary: {}", cli_args.program);
    loader_log!("  Entry point: 0x{:X}", pe_loader.entry_point());
    loader_log!("  Image base: 0x{:X}", pe_loader.image_base());
    loader_log!("  Sections: {}", pe_loader.section_count());

    // Get section information
    let sections = pe_loader
        .sections()
        .map_err(|e| anyhow!("Failed to get sections: {e}"))?;

    loader_log!("\nSections:");
    for section in &sections {
        let is_bss = section.virtual_size > 0 && section.data.is_empty();
        let section_type = if is_bss {
            " (BSS - uninitialized)"
        } else if section.data.len() < section.virtual_size as usize {
            " (partial BSS)"
        } else {
            ""
        };
        loader_log!(
            "  {} - VA: 0x{:X}, VSize: {} bytes, RawSize: {} bytes, Characteristics: 0x{:X}{}",
            section.name,
            section.virtual_address,
            section.virtual_size,
            section.data.len(),
            section.characteristics,
            section_type
        );
    }

    // Set up tracing if enabled
    let trace_config = if cli_args.trace_apis {
        let format = match cli_args.trace_format.as_str() {
            "json" => TraceFormat::Json,
            _ => TraceFormat::Text,
        };

        let output = match &cli_args.trace_output {
            Some(path) => TraceOutput::File(path.clone()),
            None => TraceOutput::Stdout,
        };

        TraceConfig::enabled()
            .with_format(format)
            .with_output(output)
    } else {
        TraceConfig::default()
    };

    // Set up trace filters
    let mut trace_filter = TraceFilter::new();
    if let Some(pattern) = &cli_args.trace_filter {
        trace_filter = trace_filter.add_rule(FilterRule::Pattern(pattern.clone()));
    }
    if let Some(category_str) = &cli_args.trace_category {
        let category = match category_str.as_str() {
            "file_io" => ApiCategory::FileIo,
            "console_io" => ApiCategory::ConsoleIo,
            "memory" => ApiCategory::Memory,
            _ => {
                return Err(anyhow!(
                    "Invalid category '{category_str}'. Valid options: file_io, console_io, memory",
                ));
            }
        };
        trace_filter = trace_filter.add_rule(FilterRule::Category(vec![category]));
    }

    // Create tracer
    let tracer = Arc::new(
        Tracer::new(trace_config, trace_filter)
            .map_err(|e| anyhow!("Failed to create tracer: {e}"))?,
    );

    // Initialize the platform (wrapped with tracing if enabled)
    let platform = LinuxPlatformForWindows::new();

    // Initialize trampolines for MSVCRT and other functions
    // SAFETY: This allocates executable memory for calling convention translation
    unsafe {
        platform
            .initialize_trampolines(verbose)
            .map_err(|e| anyhow!("Failed to initialize trampolines: {e}"))?;
    }
    platform
        .link_trampolines_to_dll_manager(verbose)
        .map_err(|e| anyhow!("Failed to link trampolines to DLL manager: {e}"))?;

    // Link data exports to actual memory addresses
    // SAFETY: This only takes addresses of static variables
    unsafe {
        platform
            .link_data_exports_to_dll_manager()
            .map_err(|e| anyhow!("Failed to link data exports: {e}"))?;
    }

    // Populate the dynamic-export registry used by LoadLibraryW/GetProcAddress.
    // This must be done after trampolines are linked so the addresses are valid.
    register_dynamic_exports(&platform.export_dll_addresses());

    loader_log!("Initialized function trampolines for MSVCRT");

    let mut platform = TracedNtdllApi::new(platform, tracer);

    // Calculate total image size (find max virtual address + size)
    let image_size = sections
        .iter()
        .filter_map(|s| (s.virtual_address as usize).checked_add(s.virtual_size as usize))
        .max()
        .ok_or_else(|| anyhow!("Failed to calculate image size: overflow or no sections"))?;

    loader_log!("\nAllocating memory for PE image:");
    loader_log!(
        "  Image size: {} bytes ({} KB)",
        image_size,
        image_size / 1024
    );

    // Allocate memory for the PE image with read/write/execute permissions
    let base_address = platform
        .nt_allocate_virtual_memory(image_size, memory_protection::PAGE_EXECUTE_READWRITE)?;

    loader_log!("  Allocated at: 0x{base_address:X}");

    // Load sections into the allocated memory
    loader_log!("\nLoading sections into memory...");
    // SAFETY: We just allocated memory of the correct size with the platform
    let loaded_size = unsafe {
        pe_loader
            .load_sections(base_address)
            .map_err(|e| anyhow!("Failed to load sections: {e}"))?
    };
    loader_log!("  Loaded {loaded_size} bytes");

    // Apply relocations if needed
    loader_log!("\nApplying relocations...");
    let image_base = pe_loader.image_base();
    if base_address == image_base {
        loader_log!("  No relocations needed (loaded at preferred base)");
    } else {
        loader_log!("  Rebasing from 0x{image_base:X} to 0x{base_address:X}");

        // Get relocation count for debugging
        let reloc_count = pe_loader.relocations().map(|r| r.len()).unwrap_or(0);
        loader_log!("  Found {reloc_count} relocation entries");

        // SAFETY: We allocated the memory and just loaded the sections
        unsafe {
            pe_loader
                .apply_relocations(image_base, base_address)
                .map_err(|e| anyhow!("Failed to apply relocations: {e}"))?;
        }
        loader_log!("  Relocations applied successfully");
    }

    // Patch __CTOR_LIST__ after relocations to fix MinGW constructor sentinel issues
    // Must be done after relocations so pointer values are correct
    loader_log!("\nPatching __CTOR_LIST__ for MinGW compatibility...");
    // SAFETY: Sections are loaded and relocations are applied
    unsafe {
        pe_loader
            .patch_ctor_list(base_address)
            .map_err(|e| anyhow!("Failed to patch __CTOR_LIST__: {e}"))?;
    }
    loader_log!("  __CTOR_LIST__ patching complete");

    // Resolve imports
    loader_log!("\nResolving imports...");
    let imports = pe_loader
        .imports()
        .map_err(|e| anyhow!("Failed to get imports: {e}"))?;

    if imports.is_empty() {
        loader_log!("  No imports found");
    } else {
        for import_dll in &imports {
            loader_log!("  DLL: {}", import_dll.name);
            loader_log!("    Functions: {}", import_dll.functions.len());

            // Print all function names first
            for func_name in &import_dll.functions {
                loader_log!("      {func_name}");
            }

            // Load the DLL and resolve function addresses
            let dll_handle = platform
                .load_library(&import_dll.name)
                .map_err(|e| anyhow!("Failed to load DLL {}: {e}", import_dll.name))?;

            let mut resolved_addresses = Vec::new();
            for func_name in &import_dll.functions {
                match platform.get_proc_address(dll_handle, func_name) {
                    Ok(addr) => {
                        resolved_addresses.push(addr);
                        loader_log!("      {func_name} -> 0x{addr:X}");
                    }
                    Err(e) => {
                        loader_log!("      {func_name} -> NOT FOUND ({e})");
                        // Use a stub address (0) for missing functions
                        resolved_addresses.push(0);
                    }
                }
            }

            // Write resolved addresses to IAT
            // SAFETY: We allocated the memory and loaded the sections
            unsafe {
                pe_loader
                    .write_iat(
                        base_address,
                        &import_dll.name,
                        import_dll.iat_rva,
                        &resolved_addresses,
                    )
                    .map_err(|e| anyhow!("Failed to write IAT: {e}"))?;
            }
        }
        loader_log!("  Import resolution complete");
    }

    // Parse and initialize TLS (Thread Local Storage)
    loader_log!("\nChecking for TLS directory...");
    let tls_info = pe_loader
        .tls_info()
        .map_err(|e| anyhow!("Failed to parse TLS directory: {e}"))?;

    // Register the exception table (.pdata) for SEH support
    loader_log!("\nChecking for exception directory (.pdata)...");
    let exception_dir = pe_loader
        .exception_directory()
        .map_err(|e| anyhow!("Failed to parse exception directory: {e}"))?;
    if let Some(ref exc) = exception_dir {
        // The .pdata RVAs are relative to the image base; since relocations have
        // already been applied to the *section data*, we pass the actual load address
        // and the original RVA so RtlLookupFunctionEntry can add them at lookup time.
        register_exception_table(base_address, exc.rva, exc.size);
        loader_log!(
            "  Exception table registered: {} entries ({} bytes) at RVA 0x{:X}",
            exc.size / 12,
            exc.size,
            exc.rva,
        );
    } else {
        loader_log!("  No exception directory found");
    }

    // Set up execution context (TEB/PEB)
    loader_log!("\nSetting up execution context...");
    let mut execution_context =
        ExecutionContext::new(base_address, 0) // Use default stack size
            .map_err(|e| anyhow!("Failed to create execution context: {e}"))?;
    loader_log!("  TEB created at: 0x{:X}", execution_context.teb_address);
    loader_log!(
        "  PEB created with image base: 0x{:X}",
        execution_context.peb.image_base_address
    );
    loader_log!(
        "  Stack range: 0x{:X} - 0x{:X} ({} KB)",
        execution_context.stack_base,
        execution_context.stack_base - execution_context.stack_size,
        execution_context.stack_size / 1024
    );

    // Initialize TLS if present
    if let Some(tls) = tls_info {
        loader_log!("\nInitializing TLS (Thread Local Storage)...");
        loader_log!(
            "  TLS data range (VA): 0x{:X} - 0x{:X}",
            tls.start_address,
            tls.end_address
        );
        loader_log!("  TLS index address (VA): 0x{:X}", tls.address_of_index);
        loader_log!("  Size of zero fill: {} bytes", tls.size_of_zero_fill);

        // The TLS directory contains VAs (virtual addresses), which include the image base.
        // Since the image might be loaded at a different address, we need to calculate
        // the actual addresses by removing the original image base and adding the actual base.
        let delta = base_address.wrapping_sub(image_base);
        let actual_start = tls.start_address.wrapping_add(delta);
        let actual_end = tls.end_address.wrapping_add(delta);
        let actual_index = tls.address_of_index.wrapping_add(delta);

        loader_log!("  TLS data range (relocated): 0x{actual_start:X} - 0x{actual_end:X}");
        loader_log!("  TLS index address (relocated): 0x{actual_index:X}");

        // SAFETY: We allocated memory for the image and loaded sections.
        // The TLS addresses are from the TLS directory and point to valid memory.
        unsafe {
            execution_context
                .initialize_tls(
                    base_address,
                    actual_start,
                    actual_end,
                    actual_index,
                    tls.size_of_zero_fill,
                )
                .map_err(|e| anyhow!("Failed to initialize TLS: {e}"))?;
        }
        loader_log!(
            "  TLS initialized, slot[0] = 0x{:X}",
            execution_context.teb.tls_slots[0]
        );

        // Execute TLS callbacks if present.
        if tls.address_of_callbacks != 0 {
            let actual_callbacks = tls.address_of_callbacks.wrapping_add(delta);
            loader_log!("  Executing TLS callbacks from table at: 0x{actual_callbacks:X}");

            // Validate that the callback table lies within the mapped image range.
            #[allow(clippy::cast_possible_truncation)]
            let image_size_u64 = image_size as u64;
            let image_end = base_address
                .checked_add(image_size_u64)
                .ok_or_else(|| anyhow!("image size overflow when computing image end"))?;
            if actual_callbacks < base_address || actual_callbacks >= image_end {
                return Err(anyhow!(
                    "TLS callbacks table address 0x{actual_callbacks:X} is outside image range \
                     0x{base_address:X}-0x{image_end:X}"
                ));
            }

            // Derive a hard cap on the number of callbacks based on remaining image space.
            // This prevents unbounded reads if the table lacks a NULL terminator.
            let max_callbacks = (image_end - actual_callbacks) / core::mem::size_of::<u64>() as u64;
            if max_callbacks == 0 {
                return Err(anyhow!(
                    "TLS callbacks table at 0x{actual_callbacks:X} has no room for entries"
                ));
            }

            // Walk the NULL-terminated array of callback function pointers, but never
            // read past the end of the image.
            #[allow(clippy::cast_possible_truncation)]
            let mut cb_ptr = actual_callbacks as *const u64;
            let mut found_terminator = false;
            for _ in 0..max_callbacks {
                // SAFETY: cb_ptr is derived from a validated address within the mapped image.
                // We use read_unaligned because the callback array may not be
                // naturally aligned for u64, and the data comes from a PE file.
                let cb_addr = unsafe { core::ptr::read_unaligned(cb_ptr) };
                if cb_addr == 0 {
                    found_terminator = true;
                    break;
                }
                loader_log!("    Calling TLS callback at: 0x{cb_addr:X}");
                // Call with (base_address, DLL_PROCESS_ATTACH=1, NULL).
                // Windows TLS callbacks use the Windows x64 calling convention
                // (args in RCX, RDX, R8 with 32-byte shadow space), not System V
                // (args in RDI, RSI, RDX).  Use `extern "win64"` to generate the
                // correct call sequence from this Linux Rust binary.
                //
                // SAFETY: cb_addr is a valid code address inside the loaded image.
                #[allow(clippy::cast_possible_truncation)]
                let callback: unsafe extern "win64" fn(u64, u32, *mut u8) =
                    unsafe { core::mem::transmute(cb_addr as usize) };
                unsafe { callback(base_address, 1, core::ptr::null_mut()) };
                // SAFETY: We stay within the bounds implied by max_callbacks.
                cb_ptr = unsafe { cb_ptr.add(1) };
            }

            if !found_terminator {
                return Err(anyhow!(
                    "TLS callbacks table at 0x{actual_callbacks:X} is not NULL-terminated \
                     within the image bounds"
                ));
            }
        }
    } else {
        loader_log!("\nNo TLS directory found");
    }

    // Set up GS segment register to point to TEB for Windows ABI compatibility
    loader_log!("\nConfiguring GS segment register for TEB access...");
    // Set GS base to TEB address using the wrgsbase instruction
    // This enables Windows programs to access TEB via gs:[0x60] (PEB pointer offset)
    // SAFETY: We're setting the GS base to a valid TEB address that we just allocated.
    // The TEB structure is properly initialized with valid pointers.
    // On x86_64 systems (required by this crate), u64 addresses fit in usize without truncation.
    #[allow(clippy::cast_possible_truncation)]
    unsafe {
        litebox_common_linux::wrgsbase(execution_context.teb_address as usize);
    }
    loader_log!(
        "  GS base register set to TEB address: 0x{:X}",
        execution_context.teb_address
    );

    // Calculate entry point address
    let entry_point_rva = pe_loader.entry_point();
    let entry_point_address = base_address + entry_point_rva;

    loader_log!("\n[Phase 6 Progress]");
    loader_log!("  ✓ PE loader");
    loader_log!("  ✓ Section loading");
    loader_log!("  ✓ Relocation processing");
    loader_log!("  ✓ Import resolution");
    loader_log!("  ✓ IAT patching");
    loader_log!("  ✓ TEB/PEB setup");
    loader_log!("  → Entry point at: 0x{entry_point_address:X}");

    // Set the process command line so Windows APIs (GetCommandLineW, __getmainargs) return
    // the correct arguments.  Build argv as [program_name, extra_args...].
    let mut cmd_args = vec![cli_args.program.clone()];
    cmd_args.extend(cli_args.arguments.iter().cloned());
    set_process_command_line(&cmd_args);

    // If a sandbox root was requested, configure it now (before any file I/O).
    if let Some(root) = &cli_args.root {
        set_sandbox_root(root);
        loader_log!("Sandbox root: {root}");
    }

    // Configure the volume serial number.  When the user supplies --volume-serial
    // we pin that value; otherwise get_volume_serial() will generate one lazily.
    if let Some(serial) = cli_args.volume_serial {
        set_volume_serial(serial);
        loader_log!("Volume serial: 0x{serial:08X}");
    }

    // Attempt to call the entry point
    // NOTE: This will likely fail in practice because:
    // 1. We don't have actual Windows DLL implementations (only stubs)
    // 2. Stack setup is minimal
    // 3. ABI translation is incomplete
    loader_log!("\nAttempting to call entry point...");
    loader_log!("WARNING: Entry point execution is experimental and may crash!");
    loader_log!("         Most Windows programs will fail due to missing DLL implementations.");

    // Debug: Print first 16 bytes at entry point
    if verbose {
        loader_log!("\nDebug: First 16 bytes at entry point:");
        #[allow(clippy::cast_possible_truncation)]
        unsafe {
            let entry_bytes = core::slice::from_raw_parts(entry_point_address as *const u8, 16);
            print!("  ");
            for (i, byte) in entry_bytes.iter().enumerate() {
                print!("{byte:02X} ");
                if i == 7 {
                    print!(" ");
                }
            }
            println!();
        }
    }

    // Try to call the entry point
    // Note: On 64-bit systems, u64 addresses fit in usize. On 32-bit systems,
    // addresses > 4GB would be truncated, but Windows PE files on 32-bit systems
    // use 32-bit addresses anyway, so this is safe in practice.
    #[allow(clippy::cast_possible_truncation)]
    match unsafe { call_entry_point(entry_point_address as usize, &execution_context) } {
        Ok(exit_code) => {
            loader_log!("\n✓ Entry point executed successfully!");
            loader_log!("  Exit code: {exit_code}");
        }
        Err(e) => {
            loader_log!("\n✗ Entry point execution failed: {e}");
            loader_log!("  This is expected for most Windows programs at this stage.");
            loader_log!("  Full Windows API implementations are needed for actual execution.");
        }
    }

    // For Phase 6 demo: Show that we can do basic console I/O through the platform
    let stdout_handle = platform.get_std_output();
    platform.write_console(stdout_handle, "\nHello from Windows on Linux!\n")?;

    // Clean up allocated memory
    platform.nt_free_virtual_memory(base_address, image_size)?;
    loader_log!("\nMemory deallocated successfully.");

    loader_log!(
        "\n[Progress: PE loader, section loading, basic NTDLL APIs, API tracing, and DLL loading implemented]"
    );
    if cli_args.trace_apis {
        loader_log!(
            "Tracing enabled: format={}, output={:?}",
            cli_args.trace_format,
            cli_args
                .trace_output
                .as_ref()
                .map_or("stdout", |p| p.to_str().unwrap_or("?"))
        );
    }

    Ok(())
}
