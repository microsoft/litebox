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
    /// ProcessEnvironmentBlock (pointer to PEB)
    pub const PEB_PTR: usize = 0x0060;
    /// LastErrorValue
    pub const LAST_ERROR: usize = 0x0068;
    /// ThreadLocalStoragePointer
    pub const TLS_POINTER: usize = 0x0058;
}

/// Offsets within the 64-bit PEB structure.
///
/// Reference: <https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB>
pub mod peb_offsets {
    /// ImageBaseAddress
    pub const IMAGE_BASE_ADDRESS: usize = 0x0010;
    /// ProcessHeap
    pub const PROCESS_HEAP: usize = 0x0030;
    /// ProcessParameters (pointer to RTL_USER_PROCESS_PARAMETERS)
    pub const PROCESS_PARAMETERS: usize = 0x0020;
    /// Number of processors
    pub const NUMBER_OF_PROCESSORS: usize = 0x00B8;
    /// OSMajorVersion
    pub const OS_MAJOR_VERSION: usize = 0x0118;
    /// OSMinorVersion
    pub const OS_MINOR_VERSION: usize = 0x011C;
    /// OSBuildNumber
    pub const OS_BUILD_NUMBER: usize = 0x0120;
}

/// Offsets within RTL_USER_PROCESS_PARAMETERS.
pub mod process_params_offsets {
    /// CommandLine (UNICODE_STRING at offset 0x70)
    pub const COMMAND_LINE_LENGTH: usize = 0x0070; // USHORT Length
    pub const COMMAND_LINE_MAX_LENGTH: usize = 0x0072; // USHORT MaximumLength
    pub const COMMAND_LINE_BUFFER: usize = 0x0078; // PWSTR Buffer
    /// ImagePathName (UNICODE_STRING at offset 0x60)
    pub const IMAGE_PATH_LENGTH: usize = 0x0060;
    pub const IMAGE_PATH_MAX_LENGTH: usize = 0x0062;
    pub const IMAGE_PATH_BUFFER: usize = 0x0068;
    /// Environment (pointer at offset 0x80)
    pub const ENVIRONMENT: usize = 0x0080;
    /// StandardInput handle (at offset 0x18)
    pub const STD_INPUT_HANDLE: usize = 0x0018;
    /// StandardOutput handle (at offset 0x20)
    pub const STD_OUTPUT_HANDLE: usize = 0x0020;
    /// StandardError handle (at offset 0x28)
    pub const STD_ERROR_HANDLE: usize = 0x0028;
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

/// Size of the environment block buffer (1 page).
pub const ENV_BLOCK_SIZE: usize = 0x1000;

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
    /// Total size of the PEB/TEB allocation region.
    pub total_size: usize,
}

impl PebTebLayout {
    /// Compute the PEB/TEB layout at a given base address.
    ///
    /// Layout (contiguous):
    /// ```text
    /// [TEB: 2 pages][PEB: 1 page][ProcessParams: 1 page][CmdLineW: 1 page][CmdLineA: 1 page][EnvBlock: 1 page]
    /// ```
    pub fn at_base(base_va: usize) -> Self {
        let cmdline_va = base_va + TEB_SIZE + PEB_SIZE + PROCESS_PARAMS_SIZE;
        let cmdline_ansi_va = cmdline_va + CMDLINE_BUFFER_SIZE;
        let env_block_va = cmdline_ansi_va + CMDLINE_ANSI_BUFFER_SIZE;
        Self {
            teb_va: base_va,
            peb_va: base_va + TEB_SIZE,
            process_params_va: base_va + TEB_SIZE + PEB_SIZE,
            cmdline_buffer_va: cmdline_va,
            cmdline_ansi_buffer_va: cmdline_ansi_va,
            env_block_va,
            total_size: TEB_SIZE
                + PEB_SIZE
                + PROCESS_PARAMS_SIZE
                + CMDLINE_BUFFER_SIZE
                + CMDLINE_ANSI_BUFFER_SIZE
                + ENV_BLOCK_SIZE,
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
    /// Process heap base address.
    pub process_heap: usize,
    /// Command line as a wide string (UTF-16LE, without null terminator).
    pub command_line_wide: alloc::vec::Vec<u16>,
    /// Standard I/O handle values (from the handle table).
    pub stdin_handle: u64,
    pub stdout_handle: u64,
    pub stderr_handle: u64,
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
    // ProcessEnvironmentBlock
    write_u64(teb, teb_offsets::PEB_PTR, layout.peb_va as u64);
    // LastErrorValue = 0
    write_u32(teb, teb_offsets::LAST_ERROR, 0);

    // ---- PEB ----
    let peb_start = TEB_SIZE;
    let peb = &mut data[peb_start..peb_start + PEB_SIZE];

    // ImageBaseAddress
    write_u64(
        peb,
        peb_offsets::IMAGE_BASE_ADDRESS,
        params.image_base as u64,
    );
    // ProcessParameters
    write_u64(
        peb,
        peb_offsets::PROCESS_PARAMETERS,
        layout.process_params_va as u64,
    );
    // ProcessHeap
    write_u64(peb, peb_offsets::PROCESS_HEAP, params.process_heap as u64);
    // NumberOfProcessors = 1
    write_u32(peb, peb_offsets::NUMBER_OF_PROCESSORS, 1);
    // OS version: Windows 10.0.19041
    write_u32(peb, peb_offsets::OS_MAJOR_VERSION, 10);
    write_u32(peb, peb_offsets::OS_MINOR_VERSION, 0);
    write_u16(peb, peb_offsets::OS_BUILD_NUMBER, 19041);

    // ---- RTL_USER_PROCESS_PARAMETERS ----
    let pp_start = TEB_SIZE + PEB_SIZE;
    let pp = &mut data[pp_start..pp_start + PROCESS_PARAMS_SIZE];

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
        cmdline_byte_len,
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

    data
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
        );
    }

    #[test]
    fn peb_teb_bytes_roundtrip() {
        let layout = PebTebLayout::at_base(0x1000_0000);
        let params = PebTebParams {
            stack_base: 0x7FFE_FFFF_0000,
            stack_limit: 0x7FFE_FFF0_0000,
            image_base: 0x0040_0000,
            process_heap: 0x0050_0000,
            command_line_wide: "hello.exe".encode_utf16().collect(),
            stdin_handle: 4,
            stdout_handle: 8,
            stderr_handle: 12,
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
    }
}
