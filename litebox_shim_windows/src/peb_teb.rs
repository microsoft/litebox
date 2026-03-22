// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! PEB and TEB synthesis for the NT shim.
//!
//! Creates minimal Process Environment Block (PEB) and Thread Environment
//! Block (TEB) structures in guest memory. These are the minimum fields
//! needed for a static hello-world PE to function:
//!
//! - TEB: pointer to PEB, stack limits, TLS array
//! - PEB: process heap, command line (RTL_USER_PROCESS_PARAMETERS)

use alloc::vec;

/// Offsets within the 64-bit TEB structure.
///
/// We only populate the fields that Phase 1 code actually reads.
/// Reference: <https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_TEB>
pub mod teb_offsets {
    /// NtTib.ExceptionList (not used but must be a valid-looking pointer or -1)
    pub const EXCEPTION_LIST: usize = 0x0000;
    /// NtTib.StackBase
    pub const STACK_BASE: usize = 0x0008;
    /// NtTib.StackLimit
    pub const STACK_LIMIT: usize = 0x0010;
    /// NtTib.Self (pointer to TEB itself)
    pub const SELF: usize = 0x0030;
    /// ClientId.UniqueProcess (HANDLE)
    pub const CLIENT_ID_PROCESS: usize = 0x0040;
    /// ClientId.UniqueThread (HANDLE)
    pub const CLIENT_ID_THREAD: usize = 0x0048;
    /// ThreadLocalStoragePointer
    pub const TLS_POINTER: usize = 0x0058;
    /// ProcessEnvironmentBlock (pointer to PEB)
    pub const PEB_PTR: usize = 0x0060;
    /// LastErrorValue
    pub const LAST_ERROR: usize = 0x0068;
    /// DeallocationStack — base of the stack allocation (lowest address).
    /// ntdll's `RtlpGetStackLimits` returns STATUS_BAD_STACK when this is 0.
    pub const DEALLOCATION_STACK: usize = 0x1478;
    /// GuaranteedStackBytes — minimum stack guarantee for the thread.
    pub const GUARANTEED_STACK_BYTES: usize = 0x1748;
}

/// Offsets within the 64-bit PEB structure.
///
/// Reference: <https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB>
pub mod peb_offsets {
    /// Mutant (HANDLE) = -1
    pub const MUTANT: usize = 0x0008;
    /// ImageBaseAddress
    pub const IMAGE_BASE_ADDRESS: usize = 0x0010;
    /// Ldr (PPEB_LDR_DATA)
    pub const LDR: usize = 0x0018;
    /// ProcessParameters (pointer to RTL_USER_PROCESS_PARAMETERS)
    pub const PROCESS_PARAMETERS: usize = 0x0020;
    /// ProcessHeap
    pub const PROCESS_HEAP: usize = 0x0030;
    /// FastPebLock (PRTL_CRITICAL_SECTION)
    pub const FAST_PEB_LOCK: usize = 0x0038;
    /// ApiSetMap (pointer to API_SET_NAMESPACE)
    pub const API_SET_MAP: usize = 0x0068;
    /// ReadOnlySharedMemoryBase (used in rebasing ReadOnlyStaticServerData pointers)
    pub const READ_ONLY_SHARED_MEMORY_BASE: usize = 0x0088;
    /// ReadOnlyStaticServerData (pointer to array of per-server-DLL data pointers)
    /// Normally populated by CSRSS during CsrClientConnectToServer.
    pub const READ_ONLY_STATIC_SERVER_DATA: usize = 0x0098;
    /// Number of processors
    pub const NUMBER_OF_PROCESSORS: usize = 0x00B8;
    /// CriticalSectionTimeout (LARGE_INTEGER at offset 0xC0)
    /// Negative = relative 100ns units. Default ~30 days = -0x19DB1DED0000.
    pub const CRITICAL_SECTION_TIMEOUT: usize = 0x00C0;
    /// OSMajorVersion
    pub const OS_MAJOR_VERSION: usize = 0x0118;
    /// OSMinorVersion
    pub const OS_MINOR_VERSION: usize = 0x011C;
    /// OSBuildNumber
    pub const OS_BUILD_NUMBER: usize = 0x0120;
    /// OSPlatformId (VER_PLATFORM_WIN32_NT = 2)
    pub const OS_PLATFORM_ID: usize = 0x0124;
    /// ImageSubsystem (from PE optional header)
    /// IMAGE_SUBSYSTEM_NATIVE=1, _WINDOWS_GUI=2, _WINDOWS_CUI=3
    pub const IMAGE_SUBSYSTEM: usize = 0x0128;
    /// ImageSubsystemMajorVersion
    pub const IMAGE_SUBSYSTEM_MAJOR_VERSION: usize = 0x012C;
    /// ImageSubsystemMinorVersion
    pub const IMAGE_SUBSYSTEM_MINOR_VERSION: usize = 0x0130;
    /// SessionId
    pub const SESSION_ID: usize = 0x02C0;
}

/// Offsets within RTL_USER_PROCESS_PARAMETERS.
pub mod process_params_offsets {
    /// MaximumLength of the structure (ULONG at offset 0x00)
    pub const MAXIMUM_LENGTH: usize = 0x0000;
    /// Length of the structure (ULONG at offset 0x04)
    pub const LENGTH: usize = 0x0004;
    /// Flags (ULONG at offset 0x08), bit 0 = RTL_USER_PROC_PARAMS_NORMALIZED
    pub const FLAGS: usize = 0x0008;
    /// ConsoleHandle (HANDLE at offset 0x10)
    pub const CONSOLE_HANDLE: usize = 0x0010;
    /// StandardInput handle (at offset 0x18)
    pub const STD_INPUT_HANDLE: usize = 0x0018;
    /// StandardOutput handle (at offset 0x20)
    pub const STD_OUTPUT_HANDLE: usize = 0x0020;
    /// StandardError handle (at offset 0x28)
    pub const STD_ERROR_HANDLE: usize = 0x0028;
    /// CurrentDirectory.DosPath (UNICODE_STRING at offset 0x38)
    pub const CUR_DIR_DOS_PATH_LENGTH: usize = 0x0038;
    pub const CUR_DIR_DOS_PATH_MAX_LENGTH: usize = 0x003A;
    pub const CUR_DIR_DOS_PATH_BUFFER: usize = 0x0040;
    /// CurrentDirectory.Handle (HANDLE at offset 0x48)
    pub const CUR_DIR_HANDLE: usize = 0x0048;
    /// DllPath (UNICODE_STRING at offset 0x50)
    pub const DLL_PATH_LENGTH: usize = 0x0050;
    pub const DLL_PATH_MAX_LENGTH: usize = 0x0052;
    pub const DLL_PATH_BUFFER: usize = 0x0058;
    /// ImagePathName (UNICODE_STRING at offset 0x60)
    pub const IMAGE_PATH_LENGTH: usize = 0x0060;
    pub const IMAGE_PATH_MAX_LENGTH: usize = 0x0062;
    pub const IMAGE_PATH_BUFFER: usize = 0x0068;
    /// CommandLine (UNICODE_STRING at offset 0x70)
    pub const COMMAND_LINE_LENGTH: usize = 0x0070; // USHORT Length
    pub const COMMAND_LINE_MAX_LENGTH: usize = 0x0072; // USHORT MaximumLength
    pub const COMMAND_LINE_BUFFER: usize = 0x0078; // PWSTR Buffer
    /// Environment (pointer at offset 0x80)
    pub const ENVIRONMENT: usize = 0x0080;
    /// WindowTitle (UNICODE_STRING at offset 0xB0)
    pub const WINDOW_TITLE_LENGTH: usize = 0x00B0;
    pub const WINDOW_TITLE_MAX_LENGTH: usize = 0x00B2;
    pub const WINDOW_TITLE_BUFFER: usize = 0x00B8;
}

/// Size of TEB allocation (2 pages — TEB is ~0x1000 bytes but we round up).
pub const TEB_SIZE: usize = 0x2000;
/// Size of PEB allocation (1 page).
pub const PEB_SIZE: usize = 0x1000;
/// Size of RTL_USER_PROCESS_PARAMETERS allocation (1 page).
pub const PROCESS_PARAMS_SIZE: usize = 0x1000;
/// Size of command line string buffer (1 page).
pub const CMDLINE_BUFFER_SIZE: usize = 0x1000;
/// Size of ANSI command line string buffer (1 page).
pub const CMDLINE_ANSI_BUFFER_SIZE: usize = 0x1000;

/// Size of PEB_LDR_DATA structure (must be at least 0x60 bytes).
/// Sized to keep total layout page-aligned with FAST_PEB_LOCK_SIZE.
pub const LDR_DATA_SIZE: usize = 0xC00;
/// Size of a minimal RTL_CRITICAL_SECTION (FastPebLock) — 0x28 bytes + padding.
pub const FAST_PEB_LOCK_SIZE: usize = 0x400;

/// Size of the ReadOnlyStaticServerData region.
///
/// Layout within this region:
///   +0x000: pointer array (3 × 8 = 24 bytes) — entries for basesrv, winsrv, user32
///   +0x100: BASE_STATIC_SERVER_DATA buffer (zeroed, ~2KB)
///
/// Normally populated by CSRSS during CsrClientConnectToServer. Since we patch
/// CSR out, we provide a zeroed buffer so kernelbase's init code (which reads
/// `PEB->ReadOnlyStaticServerData[1]`) doesn't crash on null dereference.
pub const STATIC_SERVER_DATA_SIZE: usize = 0x1000;

/// Size of the environment block buffer (1 page).
pub const ENV_BLOCK_SIZE: usize = 0x1000;

/// Size of the image path name buffer (1 page).
pub const IMAGE_PATH_BUFFER_SIZE: usize = 0x1000;

/// Size of the current directory path buffer (1 page).
pub const CUR_DIR_BUFFER_SIZE: usize = 0x1000;

/// Layout information for the synthesized PEB/TEB.
#[derive(Debug, Clone)]
pub struct PebTebLayout {
    /// Guest VA of the TEB.
    pub teb_va: usize,
    /// Guest VA of the PEB.
    pub peb_va: usize,
    /// Guest VA of RTL_USER_PROCESS_PARAMETERS.
    pub process_params_va: usize,
    /// Guest VA of the command line wide string buffer.
    pub cmdline_buffer_va: usize,
    /// Guest VA of the command line ANSI string buffer.
    pub cmdline_ansi_buffer_va: usize,
    /// Guest VA of the environment block (double-NUL terminated UTF-16).
    pub env_block_va: usize,
    /// Guest VA of the image path name buffer (UTF-16).
    pub image_path_buffer_va: usize,
    /// Guest VA of the current directory path buffer (UTF-16).
    pub cur_dir_buffer_va: usize,
    /// Guest VA of PEB_LDR_DATA.
    pub ldr_data_va: usize,
    /// Guest VA of FastPebLock (RTL_CRITICAL_SECTION).
    pub fast_peb_lock_va: usize,
    /// Guest VA of ReadOnlyStaticServerData region (pointer array + data buffer).
    pub static_server_data_va: usize,
    /// Total size of the PEB/TEB allocation region.
    pub total_size: usize,
}

impl PebTebLayout {
    /// Compute the PEB/TEB layout at a given base address.
    ///
    /// Layout (contiguous):
    /// ```text
    /// [TEB][PEB][ProcessParams][CmdLineW][CmdLineA][EnvBlock][ImagePath][CurDir][LdrData][FastPebLock][StaticServerData]
    /// ```
    pub fn at_base(base_va: usize) -> Self {
        let cmdline_va = base_va + TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE;
        let cmdline_ansi_va = cmdline_va + CMDLINE_BUFFER_SIZE;
        let env_block_va = cmdline_ansi_va + CMDLINE_ANSI_BUFFER_SIZE;
        let image_path_va = env_block_va + ENV_BLOCK_SIZE;
        let cur_dir_va = image_path_va + IMAGE_PATH_BUFFER_SIZE;
        let ldr_data_va = cur_dir_va + CUR_DIR_BUFFER_SIZE;
        let fast_peb_lock_va = ldr_data_va + LDR_DATA_SIZE;
        let static_server_data_va = fast_peb_lock_va + FAST_PEB_LOCK_SIZE;
        Self {
            teb_va: base_va,
            peb_va: base_va + TEB_SIZE,
            process_params_va: base_va + TEB_SIZE + PEB_SIZE,
            cmdline_buffer_va: cmdline_va,
            cmdline_ansi_buffer_va: cmdline_ansi_va,
            env_block_va,
            image_path_buffer_va: image_path_va,
            cur_dir_buffer_va: cur_dir_va,
            ldr_data_va,
            fast_peb_lock_va,
            static_server_data_va,
            total_size: TEB_SIZE
                + PEB_SIZE
                + PROCESS_PARAMS_SIZE
                + CMDLINE_BUFFER_SIZE
                + CMDLINE_ANSI_BUFFER_SIZE
                + ENV_BLOCK_SIZE
                + IMAGE_PATH_BUFFER_SIZE
                + CUR_DIR_BUFFER_SIZE
                + LDR_DATA_SIZE
                + FAST_PEB_LOCK_SIZE
                + STATIC_SERVER_DATA_SIZE,
        }
    }
}

/// Parameters for PEB/TEB initialization.
#[derive(Debug)]
pub struct PebTebParams {
    /// Stack base (high address, top of stack allocation).
    pub stack_base: usize,
    /// Stack limit (low address, bottom of stack allocation).
    pub stack_limit: usize,
    /// Image base address of the main executable.
    pub image_base: usize,
    /// Size of the main executable image.
    pub image_size: usize,
    /// Process heap base address.
    pub process_heap: usize,
    /// Command line as a wide string (UTF-16LE, without null terminator).
    pub command_line_wide: alloc::vec::Vec<u16>,
    /// NT-style image path (e.g. `\??\C:\app\node.exe`) as UTF-16LE.
    pub image_path_wide: alloc::vec::Vec<u16>,
    /// DOS-style full path for LDR FullDllName (e.g. `C:\app\node.exe`).
    pub exe_full_path: alloc::vec::Vec<u16>,
    /// Base filename for LDR BaseDllName (e.g. `node.exe`).
    pub exe_base_name: alloc::vec::Vec<u16>,
    /// Standard I/O handle values (from the handle table).
    pub stdin_handle: u64,
    pub stdout_handle: u64,
    pub stderr_handle: u64,
    /// ntdll base address in guest memory.
    pub ntdll_base: usize,
    /// ntdll image size.
    pub ntdll_size: usize,
    /// Synthetic process ID (must match what NtQueryInformationProcess returns).
    pub process_id: u64,
    /// Synthetic thread ID for the initial thread.
    pub thread_id: u64,
    /// Address of the host's API_SET_NAMESPACE. ntdll uses this to resolve
    /// api-ms-win-core-* imports to their actual DLLs (e.g., kernelbase.dll).
    /// If 0, a minimal empty namespace is synthesized in the PEB page.
    pub api_set_map: usize,
}

/// Build the raw bytes for the TEB/PEB/ProcessParams region.
///
/// Returns a byte vector of `layout.total_size` bytes that should be
/// mapped as RW at `layout.teb_va` in guest memory.
pub fn build_peb_teb_bytes(layout: &PebTebLayout, params: &PebTebParams) -> alloc::vec::Vec<u8> {
    let mut data = vec![0u8; layout.total_size];

    // ---- TEB ----
    let teb = &mut data[0..TEB_SIZE];

    // NtTib.ExceptionList = -1 (no SEH chain)
    write_u64(teb, teb_offsets::EXCEPTION_LIST, u64::MAX);
    // NtTib.StackBase
    write_u64(teb, teb_offsets::STACK_BASE, params.stack_base as u64);
    // NtTib.StackLimit
    write_u64(teb, teb_offsets::STACK_LIMIT, params.stack_limit as u64);
    // NtTib.Self = pointer to TEB itself
    write_u64(teb, teb_offsets::SELF, layout.teb_va as u64);
    // ClientId.UniqueProcess
    write_u64(teb, teb_offsets::CLIENT_ID_PROCESS, params.process_id);
    // ClientId.UniqueThread
    write_u64(teb, teb_offsets::CLIENT_ID_THREAD, params.thread_id);
    // ProcessEnvironmentBlock
    write_u64(teb, teb_offsets::PEB_PTR, layout.peb_va as u64);
    // LastErrorValue = 0
    write_u32(teb, teb_offsets::LAST_ERROR, 0);
    // DeallocationStack = stack_limit (base of the stack allocation).
    // ntdll's RtlpGetStackLimits returns STATUS_BAD_STACK when this is 0.
    write_u64(
        teb,
        teb_offsets::DEALLOCATION_STACK,
        params.stack_limit as u64,
    );
    // GuaranteedStackBytes — minimum stack guarantee (default 4KB).
    write_u64(teb, teb_offsets::GUARANTEED_STACK_BYTES, 0x1000);

    // ---- PEB ----
    let peb_start = TEB_SIZE;
    let peb = &mut data[peb_start..peb_start + PEB_SIZE];

    // Mutant = -1 (INVALID_HANDLE_VALUE)
    write_u64(peb, peb_offsets::MUTANT, u64::MAX);
    // ImageBaseAddress
    write_u64(
        peb,
        peb_offsets::IMAGE_BASE_ADDRESS,
        params.image_base as u64,
    );
    // Ldr = pointer to PEB_LDR_DATA
    write_u64(peb, peb_offsets::LDR, layout.ldr_data_va as u64);
    // ProcessParameters
    write_u64(
        peb,
        peb_offsets::PROCESS_PARAMETERS,
        layout.process_params_va as u64,
    );
    // ProcessHeap
    write_u64(peb, peb_offsets::PROCESS_HEAP, params.process_heap as u64);
    // FastPebLock = pointer to RTL_CRITICAL_SECTION
    write_u64(
        peb,
        peb_offsets::FAST_PEB_LOCK,
        layout.fast_peb_lock_va as u64,
    );

    // ApiSetMap: if the runner provided the host's real API_SET_NAMESPACE
    // address, use it directly (the guest runs in the same address space).
    // Otherwise, place a minimal empty namespace within the PEB page.
    if params.api_set_map != 0 {
        write_u64(peb, peb_offsets::API_SET_MAP, params.api_set_map as u64);
    } else {
        const API_SET_NS_OFFSET: usize = 0x800; // within the PEB page
        let api_set_va = layout.peb_va + API_SET_NS_OFFSET;
        write_u64(peb, peb_offsets::API_SET_MAP, api_set_va as u64);
        // API_SET_NAMESPACE { Version, Size, Flags, Count, EntryOffset, HashOffset, HashFactor }
        write_u32(peb, API_SET_NS_OFFSET, 7); // Version = 7
        write_u32(peb, API_SET_NS_OFFSET + 4, 28); // Size = 28 (header only)
        write_u32(peb, API_SET_NS_OFFSET + 8, 0); // Flags
        write_u32(peb, API_SET_NS_OFFSET + 12, 0); // Count = 0 (no entries)
        write_u32(peb, API_SET_NS_OFFSET + 16, 28); // EntryOffset
        write_u32(peb, API_SET_NS_OFFSET + 20, 28); // HashOffset
        write_u32(peb, API_SET_NS_OFFSET + 24, 0); // HashFactor
    }

    // ReadOnlyStaticServerData: pointer to array of per-server-DLL data pointers.
    // Kernelbase init reads [PEB+0x98][1] and dereferences it. The pointer is
    // rebased: ptr = [array[1]] - PEB[0x380] + PEB[0x88]. Since PEB[0x380] and
    // PEB[0x88] are both 0, the pointer is used directly.
    //
    // Layout within the static_server_data region:
    //   +0x000: pointer array [0] = data_va, [1] = data_va, [2] = 0
    //   +0x100: zeroed BASE_STATIC_SERVER_DATA buffer
    write_u64(
        peb,
        peb_offsets::READ_ONLY_STATIC_SERVER_DATA,
        layout.static_server_data_va as u64,
    );

    // NumberOfProcessors = 1
    write_u32(peb, peb_offsets::NUMBER_OF_PROCESSORS, 1);
    // CriticalSectionTimeout: ~30 days in negative 100ns units.
    // Zero means "timeout immediately" which causes every RtlEnterCriticalSection
    // to fail — this was the suspected root cause of STATUS_INTERNAL_ERROR.
    write_u64(
        peb,
        peb_offsets::CRITICAL_SECTION_TIMEOUT,
        (-0x19DB1DED0000_i64) as u64,
    );
    // OS version: Windows 10.0.19041
    write_u32(peb, peb_offsets::OS_MAJOR_VERSION, 10);
    write_u32(peb, peb_offsets::OS_MINOR_VERSION, 0);
    write_u16(peb, peb_offsets::OS_BUILD_NUMBER, 19041);
    // OSPlatformId = VER_PLATFORM_WIN32_NT (2)
    write_u32(peb, peb_offsets::OS_PLATFORM_ID, 2);
    // ImageSubsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI (3) for console apps.
    // The CSR connection is patched out at load time (CsrClientConnectToServer → ret 0)
    // so setting CUI here is safe and maintains compatibility with other ntdll checks
    // that read the subsystem type.
    write_u32(peb, peb_offsets::IMAGE_SUBSYSTEM, 3);
    // Subsystem version: 10.0 (Windows 10)
    write_u32(peb, peb_offsets::IMAGE_SUBSYSTEM_MAJOR_VERSION, 10);
    write_u32(peb, peb_offsets::IMAGE_SUBSYSTEM_MINOR_VERSION, 0);
    // SessionId = 1 (normal interactive session)
    write_u32(peb, peb_offsets::SESSION_ID, 1);

    // ---- ReadOnlyStaticServerData pointer array (written via `data` directly) ----
    {
        let data_va = layout.static_server_data_va + 0x100;
        let ssd_abs = layout.static_server_data_va - layout.teb_va;
        let dv = (data_va as u64).to_le_bytes();
        data[ssd_abs..ssd_abs + 8].copy_from_slice(&dv); // [0] = basesrv data
        data[ssd_abs + 8..ssd_abs + 16].copy_from_slice(&dv); // [1] = winsrv data
    }

    // ---- RTL_USER_PROCESS_PARAMETERS ----
    let pp_start = TEB_SIZE + PEB_SIZE;
    let pp = &mut data[pp_start..pp_start + PROCESS_PARAMS_SIZE];

    // Flags: RTL_USER_PROC_PARAMS_NORMALIZED (bit 0) — buffers are absolute pointers
    write_u32(pp, process_params_offsets::FLAGS, 1);

    // MaximumLength and Length of the structure itself
    write_u32(
        pp,
        process_params_offsets::MAXIMUM_LENGTH,
        PROCESS_PARAMS_SIZE as u32,
    );
    write_u32(
        pp,
        process_params_offsets::LENGTH,
        PROCESS_PARAMS_SIZE as u32,
    );

    // ImagePathName (UNICODE_STRING)
    let image_path_byte_len = (params.image_path_wide.len() * 2) as u16;
    write_u16(
        pp,
        process_params_offsets::IMAGE_PATH_LENGTH,
        image_path_byte_len,
    );
    write_u16(
        pp,
        process_params_offsets::IMAGE_PATH_MAX_LENGTH,
        image_path_byte_len + 2,
    );
    write_u64(
        pp,
        process_params_offsets::IMAGE_PATH_BUFFER,
        layout.image_path_buffer_va as u64,
    );

    // CurrentDirectory.DosPath — use "C:\" as default
    let cur_dir: &[u16] = &encode_utf16_static(b"C:\\");
    let cur_dir_byte_len = (cur_dir.len() * 2) as u16;
    write_u16(
        pp,
        process_params_offsets::CUR_DIR_DOS_PATH_LENGTH,
        cur_dir_byte_len,
    );
    write_u16(
        pp,
        process_params_offsets::CUR_DIR_DOS_PATH_MAX_LENGTH,
        cur_dir_byte_len + 2,
    );
    write_u64(
        pp,
        process_params_offsets::CUR_DIR_DOS_PATH_BUFFER,
        layout.cur_dir_buffer_va as u64,
    );

    // DllPath — empty UNICODE_STRING (ntdll will compute the search path)
    write_u16(pp, process_params_offsets::DLL_PATH_LENGTH, 0);
    write_u16(pp, process_params_offsets::DLL_PATH_MAX_LENGTH, 0);
    write_u64(pp, process_params_offsets::DLL_PATH_BUFFER, 0);

    // WindowTitle — empty UNICODE_STRING
    write_u16(pp, process_params_offsets::WINDOW_TITLE_LENGTH, 0);
    write_u16(pp, process_params_offsets::WINDOW_TITLE_MAX_LENGTH, 0);
    write_u64(pp, process_params_offsets::WINDOW_TITLE_BUFFER, 0);

    // Command line UNICODE_STRING
    let cmdline_byte_len = (params.command_line_wide.len() * 2) as u16;
    write_u16(
        pp,
        process_params_offsets::COMMAND_LINE_LENGTH,
        cmdline_byte_len,
    );
    write_u16(
        pp,
        process_params_offsets::COMMAND_LINE_MAX_LENGTH,
        cmdline_byte_len + 2, // +2 for null terminator
    );
    write_u64(
        pp,
        process_params_offsets::COMMAND_LINE_BUFFER,
        layout.cmdline_buffer_va as u64,
    );

    // Standard I/O handles
    write_u64(
        pp,
        process_params_offsets::STD_INPUT_HANDLE,
        params.stdin_handle,
    );
    write_u64(
        pp,
        process_params_offsets::STD_OUTPUT_HANDLE,
        params.stdout_handle,
    );
    write_u64(
        pp,
        process_params_offsets::STD_ERROR_HANDLE,
        params.stderr_handle,
    );

    // Environment pointer
    write_u64(
        pp,
        process_params_offsets::ENVIRONMENT,
        layout.env_block_va as u64,
    );

    // ---- Command line buffer (UTF-16LE) ----
    let cl_start = TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE;
    for (i, &wchar) in params.command_line_wide.iter().enumerate() {
        let off = cl_start + i * 2;
        if off + 2 <= data.len() {
            data[off..off + 2].copy_from_slice(&wchar.to_le_bytes());
        }
    }

    // ---- ANSI command line buffer ----
    // Simplified Latin-1 narrowing for GetCommandLineA: code points 0..=0xFF
    // are preserved, others become '?'. This matches Windows behavior for the
    // default "C" locale but not for multi-byte ANSI code pages (e.g., CJK).
    // Full WideCharToMultiByte emulation is deferred to Phase 2 if needed.
    let ansi_start = TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE + CMDLINE_BUFFER_SIZE;
    for (i, &wchar) in params.command_line_wide.iter().enumerate() {
        let off = ansi_start + i;
        if off < data.len() {
            data[off] = if wchar <= 0xFF { wchar as u8 } else { b'?' };
        }
    }
    // Null-terminate the ANSI string.
    let ansi_term = ansi_start + params.command_line_wide.len();
    if ansi_term < data.len() {
        data[ansi_term] = 0;
    }

    // ---- Environment block (UTF-16LE, double-NUL terminated) ----
    // Minimal environment for CRT init.
    let env_start =
        TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE + CMDLINE_BUFFER_SIZE + CMDLINE_ANSI_BUFFER_SIZE;
    let env_strings: &[&str] = &[
        "SYSTEMROOT=C:\\Windows",
        "COMSPEC=C:\\Windows\\System32\\cmd.exe",
        "PATH=C:\\Windows\\System32",
        "TEMP=C:\\Windows\\Temp",
        "TMP=C:\\Windows\\Temp",
    ];
    let mut off = env_start;
    for s in env_strings {
        for &b in s.as_bytes() {
            if off + 2 <= data.len() {
                data[off] = b;
                data[off + 1] = 0; // high byte of UTF-16LE
                off += 2;
            }
        }
        // NUL separator between strings
        if off + 2 <= data.len() {
            data[off] = 0;
            data[off + 1] = 0;
            off += 2;
        }
    }
    // Double-NUL terminator
    if off + 2 <= data.len() {
        data[off] = 0;
        data[off + 1] = 0;
    }

    // ---- Image path name buffer (UTF-16LE) ----
    let img_path_start = env_start + ENV_BLOCK_SIZE;
    for (i, &wchar) in params.image_path_wide.iter().enumerate() {
        let pos = img_path_start + i * 2;
        if pos + 2 <= data.len() {
            data[pos..pos + 2].copy_from_slice(&wchar.to_le_bytes());
        }
    }
    // Null-terminate
    let img_term = img_path_start + params.image_path_wide.len() * 2;
    if img_term + 2 <= data.len() {
        data[img_term] = 0;
        data[img_term + 1] = 0;
    }

    // ---- Current directory path buffer (UTF-16LE) ----
    let cur_dir_start = img_path_start + IMAGE_PATH_BUFFER_SIZE;
    write_utf16(
        &mut data[cur_dir_start..cur_dir_start + CUR_DIR_BUFFER_SIZE],
        0,
        cur_dir,
    );

    // ---- PEB_LDR_DATA + LDR_DATA_TABLE_ENTRY for EXE and ntdll ----
    // ntdll's LdrpInitializeProcess expects the kernel to have pre-populated
    // the module lists with entries for the EXE and ntdll. Without these,
    // the loader crashes on a NULL LDR entry pointer.
    //
    // Layout within the LDR region (0xC00 bytes):
    //   +0x000: PEB_LDR_DATA header (0x58 bytes)
    //   +0x060: LDR_DATA_TABLE_ENTRY for EXE (0x120 bytes)
    //   +0x180: LDR_DATA_TABLE_ENTRY for ntdll (0x120 bytes)
    //   +0x300: EXE FullDllName wide string (0x100 bytes)
    //   +0x400: EXE BaseDllName wide string (0x80 bytes)
    //   +0x480: ntdll FullDllName wide string (0x100 bytes)
    //   +0x580: ntdll BaseDllName wide string (0x80 bytes)
    let ldr_start = cur_dir_start + CUR_DIR_BUFFER_SIZE;
    let ldr = &mut data[ldr_start..ldr_start + LDR_DATA_SIZE];

    let ldr_va = layout.ldr_data_va;
    let exe_entry_va = ldr_va + 0x60;
    let ntdll_entry_va = ldr_va + 0x180;

    // PEB_LDR_DATA header
    write_u32(ldr, 0x00, 0x58); // Length
    write_u32(ldr, 0x04, 1); // Initialized = TRUE
    write_u64(ldr, 0x08, 0); // SsHandle = NULL

    // InLoadOrderModuleList: Head → EXE → ntdll → Head
    let head_load = ldr_va + 0x10;
    write_u64(ldr, 0x10, exe_entry_va as u64); // Head.Flink → EXE
    write_u64(ldr, 0x18, ntdll_entry_va as u64); // Head.Blink → ntdll

    // InMemoryOrderModuleList: Head → EXE+0x10 → ntdll+0x10 → Head
    let head_mem = ldr_va + 0x20;
    write_u64(ldr, 0x20, (exe_entry_va + 0x10) as u64);
    write_u64(ldr, 0x28, (ntdll_entry_va + 0x10) as u64);

    // InInitializationOrderModuleList: empty (ntdll populates during init)
    let head_init = ldr_va + 0x30;
    write_u64(ldr, 0x30, head_init as u64);
    write_u64(ldr, 0x38, head_init as u64);

    // ---- LDR_DATA_TABLE_ENTRY for EXE (at +0x60) ----
    let exe_off = 0x60usize;
    // InLoadOrderLinks
    write_u64(ldr, exe_off + 0x00, ntdll_entry_va as u64); // Flink → ntdll
    write_u64(ldr, exe_off + 0x08, head_load as u64); // Blink → Head
    // InMemoryOrderLinks
    write_u64(ldr, exe_off + 0x10, (ntdll_entry_va + 0x10) as u64);
    write_u64(ldr, exe_off + 0x18, head_mem as u64);
    // InInitializationOrderLinks (not linked yet)
    write_u64(ldr, exe_off + 0x20, 0);
    write_u64(ldr, exe_off + 0x28, 0);
    // DllBase
    write_u64(ldr, exe_off + 0x30, params.image_base as u64);
    // EntryPoint
    write_u64(ldr, exe_off + 0x38, 0); // filled by loader later
    // SizeOfImage
    write_u32(ldr, exe_off + 0x40, params.image_size as u32);
    // FullDllName UNICODE_STRING → name at LDR region +0x300
    let exe_full_name: &[u16] = &params.exe_full_path;
    let exe_full_name_va = ldr_va + 0x300;
    let exe_full_name_bytes = (exe_full_name.len() * 2) as u16;
    write_u16(ldr, exe_off + 0x48, exe_full_name_bytes); // Length
    write_u16(ldr, exe_off + 0x4A, exe_full_name_bytes + 2); // MaximumLength
    write_u64(ldr, exe_off + 0x50, exe_full_name_va as u64); // Buffer
    // BaseDllName UNICODE_STRING → name at LDR region +0x400
    let exe_base_name: &[u16] = &params.exe_base_name;
    let exe_base_name_va = ldr_va + 0x400;
    let exe_base_name_bytes = (exe_base_name.len() * 2) as u16;
    write_u16(ldr, exe_off + 0x58, exe_base_name_bytes);
    write_u16(ldr, exe_off + 0x5A, exe_base_name_bytes + 2);
    write_u64(ldr, exe_off + 0x60, exe_base_name_va as u64);
    // Flags: LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED
    write_u32(ldr, exe_off + 0x68, 0x00004000 | 0x00080000);
    // ObsoleteLoadCount = pinned
    write_u16(ldr, exe_off + 0x6C, 0xFFFF);
    // HashLinks (self-linked) and BaseNameHashValue
    write_u64(ldr, exe_off + 0x70, (exe_entry_va + 0x70) as u64);
    write_u64(ldr, exe_off + 0x78, (exe_entry_va + 0x70) as u64);
    // BaseNameHashValue at offset 0x108 in the entry
    write_u32(ldr, exe_off + 0x108, ldr_hash_name(exe_base_name));

    // Write EXE name strings into the LDR region
    write_utf16(ldr, 0x300, exe_full_name);
    write_utf16(ldr, 0x400, exe_base_name);

    // ---- LDR_DATA_TABLE_ENTRY for ntdll (at +0x180) ----
    let ntdll_off = 0x180usize;
    // InLoadOrderLinks
    write_u64(ldr, ntdll_off + 0x00, head_load as u64); // Flink → Head
    write_u64(ldr, ntdll_off + 0x08, exe_entry_va as u64); // Blink → EXE
    // InMemoryOrderLinks
    write_u64(ldr, ntdll_off + 0x10, head_mem as u64);
    write_u64(ldr, ntdll_off + 0x18, (exe_entry_va + 0x10) as u64);
    // InInitializationOrderLinks (not linked yet)
    write_u64(ldr, ntdll_off + 0x20, 0);
    write_u64(ldr, ntdll_off + 0x28, 0);
    // DllBase
    write_u64(ldr, ntdll_off + 0x30, params.ntdll_base as u64);
    // EntryPoint = 0 (ntdll has no DllMain)
    write_u64(ldr, ntdll_off + 0x38, 0);
    // SizeOfImage
    write_u32(ldr, ntdll_off + 0x40, params.ntdll_size as u32);
    // FullDllName → LDR region +0x480
    let ntdll_full_name: &[u16] = &encode_utf16_static(b"C:\\Windows\\System32\\ntdll.dll");
    let ntdll_full_name_va = ldr_va + 0x480;
    let ntdll_full_name_bytes = (ntdll_full_name.len() * 2) as u16;
    write_u16(ldr, ntdll_off + 0x48, ntdll_full_name_bytes);
    write_u16(ldr, ntdll_off + 0x4A, ntdll_full_name_bytes + 2);
    write_u64(ldr, ntdll_off + 0x50, ntdll_full_name_va as u64);
    // BaseDllName → LDR region +0x580
    let ntdll_base_name: &[u16] = &encode_utf16_static(b"ntdll.dll");
    let ntdll_base_name_va = ldr_va + 0x580;
    let ntdll_base_name_bytes = (ntdll_base_name.len() * 2) as u16;
    write_u16(ldr, ntdll_off + 0x58, ntdll_base_name_bytes);
    write_u16(ldr, ntdll_off + 0x5A, ntdll_base_name_bytes + 2);
    write_u64(ldr, ntdll_off + 0x60, ntdll_base_name_va as u64);
    // Flags: LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED
    write_u32(ldr, ntdll_off + 0x68, 0x00000004 | 0x00004000 | 0x00080000);
    // ObsoleteLoadCount = pinned
    write_u16(ldr, ntdll_off + 0x6C, 0xFFFF);
    // HashLinks (self-linked)
    write_u64(ldr, ntdll_off + 0x70, (ntdll_entry_va + 0x70) as u64);
    write_u64(ldr, ntdll_off + 0x78, (ntdll_entry_va + 0x70) as u64);
    // BaseNameHashValue at offset 0x108 in the entry
    write_u32(ldr, ntdll_off + 0x108, ldr_hash_name(ntdll_base_name));

    // Write ntdll name strings
    write_utf16(ldr, 0x480, ntdll_full_name);
    write_utf16(ldr, 0x580, ntdll_base_name);

    // ---- FastPebLock (RTL_CRITICAL_SECTION) ----
    // Minimal initialized critical section: OwningThread=0, RecursionCount=0,
    // LockCount=-1 (unlocked). ntdll uses this for PEB locking.
    let lock_start = ldr_start + LDR_DATA_SIZE;
    let lock = &mut data[lock_start..lock_start + FAST_PEB_LOCK_SIZE];
    // RTL_CRITICAL_SECTION layout:
    //   0x00: PRTL_CRITICAL_SECTION_DEBUG DebugInfo (NULL ok)
    //   0x08: LONG LockCount (-1 = unlocked)
    //   0x0C: LONG RecursionCount (0)
    //   0x10: HANDLE OwningThread (0)
    //   0x18: HANDLE LockSemaphore (0)
    //   0x20: ULONG_PTR SpinCount (0)
    write_u64(lock, 0x00, 0); // DebugInfo = NULL
    write_u32(lock, 0x08, 0xFFFFFFFF); // LockCount = -1 (unlocked)
    write_u32(lock, 0x0C, 0); // RecursionCount = 0
    write_u64(lock, 0x10, 0); // OwningThread = 0
    write_u64(lock, 0x18, 0); // LockSemaphore = 0
    write_u64(lock, 0x20, 0); // SpinCount = 0

    data
}

/// Compute the LDR hash value for a DLL base name.
///
/// This matches the algorithm used by `RtlHashUnicodeString` with
/// `HASH_STRING_ALGORITHM_X65599` (case-insensitive). ntdll uses this
/// to index the `LdrpHashTable` during module lookups.
fn ldr_hash_name(name: &[u16]) -> u32 {
    let mut hash: u32 = 0;
    for &ch in name {
        // Uppercase ASCII letters (simple towupper for A-Z)
        let upper = if (0x61..=0x7A).contains(&ch) {
            ch - 0x20
        } else {
            ch
        };
        hash = hash.wrapping_mul(65599).wrapping_add(upper as u32);
    }
    hash
}

fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    if offset + 8 <= buf.len() {
        buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
    }
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    if offset + 4 <= buf.len() {
        buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }
}

fn write_u16(buf: &mut [u8], offset: usize, val: u16) {
    if offset + 2 <= buf.len() {
        buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
    }
}

/// Encode an ASCII byte slice to UTF-16LE.
fn encode_utf16_static(ascii: &[u8]) -> alloc::vec::Vec<u16> {
    ascii.iter().map(|&b| b as u16).collect()
}

/// Write a UTF-16LE string (with null terminator) into a buffer at the given offset.
fn write_utf16(buf: &mut [u8], offset: usize, chars: &[u16]) {
    for (i, &ch) in chars.iter().enumerate() {
        let pos = offset + i * 2;
        if pos + 2 <= buf.len() {
            buf[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
        }
    }
    // Null terminator
    let term = offset + chars.len() * 2;
    if term + 2 <= buf.len() {
        buf[term] = 0;
        buf[term + 1] = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn peb_teb_layout_contiguous() {
        let layout = PebTebLayout::at_base(0x7FFE_1000_0000);

        assert_eq!(layout.teb_va, 0x7FFE_1000_0000);
        assert_eq!(layout.peb_va, 0x7FFE_1000_0000 + TEB_SIZE);
        assert_eq!(
            layout.process_params_va,
            0x7FFE_1000_0000 + TEB_SIZE + PEB_SIZE
        );
        assert_eq!(
            layout.total_size,
            TEB_SIZE
                + PEB_SIZE
                + PROCESS_PARAMS_SIZE
                + CMDLINE_BUFFER_SIZE
                + CMDLINE_ANSI_BUFFER_SIZE
                + ENV_BLOCK_SIZE
                + IMAGE_PATH_BUFFER_SIZE
                + CUR_DIR_BUFFER_SIZE
                + LDR_DATA_SIZE
                + FAST_PEB_LOCK_SIZE
        );
    }

    #[test]
    fn peb_teb_bytes_roundtrip() {
        let layout = PebTebLayout::at_base(0x1000_0000);
        let params = PebTebParams {
            stack_base: 0x7FFE_FFFF_0000,
            stack_limit: 0x7FFE_FFF0_0000,
            image_base: 0x0040_0000,
            image_size: 0x0010_0000,
            process_heap: 0x0050_0000,
            command_line_wide: "hello.exe".encode_utf16().collect(),
            image_path_wide: "\\??\\C:\\hello.exe".encode_utf16().collect(),
            exe_full_path: "C:\\hello.exe".encode_utf16().collect(),
            exe_base_name: "hello.exe".encode_utf16().collect(),
            stdin_handle: 4,
            stdout_handle: 8,
            stderr_handle: 12,
            ntdll_base: 0x7FFE_0000_0000,
            ntdll_size: 0x0020_0000,
            process_id: 1000,
            thread_id: 1004,
            api_set_map: 0,
        };

        let data = build_peb_teb_bytes(&layout, &params);
        assert_eq!(data.len(), layout.total_size);

        // Verify TEB.PEB pointer
        let peb_ptr = u64::from_le_bytes(
            data[teb_offsets::PEB_PTR..teb_offsets::PEB_PTR + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(peb_ptr, layout.peb_va as u64);

        // Verify TEB.Self
        let self_ptr = u64::from_le_bytes(
            data[teb_offsets::SELF..teb_offsets::SELF + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(self_ptr, layout.teb_va as u64);

        // Verify PEB.ImageBaseAddress
        let peb_off = TEB_SIZE;
        let img_base = u64::from_le_bytes(
            data[peb_off + peb_offsets::IMAGE_BASE_ADDRESS
                ..peb_off + peb_offsets::IMAGE_BASE_ADDRESS + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(img_base, 0x0040_0000);

        // Verify command line buffer contains UTF-16LE "hello.exe"
        let cl_start = TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE;
        let expected: Vec<u16> = "hello.exe".encode_utf16().collect();
        for (i, &wchar) in expected.iter().enumerate() {
            let off = cl_start + i * 2;
            let got = u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
            assert_eq!(got, wchar);
        }

        // Verify PEB.CriticalSectionTimeout is set to ~30 days (not zero)
        let cst = i64::from_le_bytes(
            data[peb_off + peb_offsets::CRITICAL_SECTION_TIMEOUT
                ..peb_off + peb_offsets::CRITICAL_SECTION_TIMEOUT + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(cst, -0x19DB1DED0000_i64);

        // Verify TEB.ClientId is populated
        let pid = u64::from_le_bytes(
            data[teb_offsets::CLIENT_ID_PROCESS..teb_offsets::CLIENT_ID_PROCESS + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(pid, 1000);
        let tid = u64::from_le_bytes(
            data[teb_offsets::CLIENT_ID_THREAD..teb_offsets::CLIENT_ID_THREAD + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(tid, 1004);

        // Verify CommandLine.MaximumLength includes +2 for null terminator
        let pp_off = TEB_SIZE + PEB_SIZE;
        let cl_len = u16::from_le_bytes(
            data[pp_off + process_params_offsets::COMMAND_LINE_LENGTH
                ..pp_off + process_params_offsets::COMMAND_LINE_LENGTH + 2]
                .try_into()
                .unwrap(),
        );
        let cl_max = u16::from_le_bytes(
            data[pp_off + process_params_offsets::COMMAND_LINE_MAX_LENGTH
                ..pp_off + process_params_offsets::COMMAND_LINE_MAX_LENGTH + 2]
                .try_into()
                .unwrap(),
        );
        assert_eq!(cl_max, cl_len + 2);
    }

    #[test]
    fn ldr_hash_name_known_values() {
        // Verify hash function produces expected values for known DLL names.
        let ntdll: Vec<u16> = "ntdll.dll".encode_utf16().collect();
        let hash = super::ldr_hash_name(&ntdll);
        // The hash must be non-zero and deterministic.
        assert_ne!(hash, 0);
        // Case-insensitive: "NTDLL.DLL" should produce the same hash.
        let ntdll_upper: Vec<u16> = "NTDLL.DLL".encode_utf16().collect();
        assert_eq!(super::ldr_hash_name(&ntdll_upper), hash);
    }
}
