// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT system information and time syscall handlers.
//!
//! Implements NtQuerySystemInformation, NtQueryPerformanceCounter,
//! NtQuerySystemTime, NtQueryInformationProcess, and NtDelayExecution.

use litebox_common_windows::ntstatus::NtStatus;

use super::NtSyscallArgs;

/// NtQuerySystemInformation — query system-level information.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQuerySystemInformation(
///     SYSTEM_INFORMATION_CLASS SystemInformationClass, // r10
///     PVOID SystemInformation,                         // rdx
///     ULONG SystemInformationLength,                   // r8
///     PULONG ReturnLength                              // r9
/// );
/// ```
pub(crate) fn nt_query_system_information(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let info_class = args.arg0 as u32;
    let info_ptr = args.arg1;
    let info_length = args.arg2 as u32;
    let return_length_ptr = args.arg3;

    match info_class {
        // SystemBasicInformation (0)
        0 => {
            // SYSTEM_BASIC_INFORMATION is 64 bytes on x64.
            const SBI_SIZE: usize = 64;
            if (info_length as usize) < SBI_SIZE || info_ptr == 0 {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, SBI_SIZE as u32);
                    }
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // Zero-fill then set key fields.
            // Layout (x64, 64 bytes):
            //   0x00 ULONG  Reserved
            //   0x04 ULONG  TimerResolution
            //   0x08 ULONG  PageSize
            //   0x0C ULONG  NumberOfPhysicalPages
            //   0x10 ULONG  LowestPhysicalPageNumber
            //   0x14 ULONG  HighestPhysicalPageNumber
            //   0x18 ULONG  AllocationGranularity
            //   0x20 ULONG_PTR MinimumUserModeAddress  (8 bytes, 8-aligned)
            //   0x28 ULONG_PTR MaximumUserModeAddress
            //   0x30 KAFFINITY ActiveProcessorsAffinityMask
            //   0x38 CCHAR  NumberOfProcessors
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, SBI_SIZE);
                let base = info_ptr as *mut u8;
                // offset 0x00: Reserved = 0 (already zero)
                // offset 0x04: TimerResolution — 100ns units, ~15.6ms
                core::ptr::write(base.add(0x04).cast::<u32>(), 156250);
                // offset 0x08: PageSize
                core::ptr::write(base.add(0x08).cast::<u32>(), 4096);
                // offset 0x0C: NumberOfPhysicalPages (~4GB)
                core::ptr::write(base.add(0x0C).cast::<u32>(), 1048576);
                // offset 0x10: LowestPhysicalPageNumber
                core::ptr::write(base.add(0x10).cast::<u32>(), 1);
                // offset 0x14: HighestPhysicalPageNumber
                core::ptr::write(base.add(0x14).cast::<u32>(), 1048576);
                // offset 0x18: AllocationGranularity
                core::ptr::write(base.add(0x18).cast::<u32>(), 65536);
                // offset 0x20: MinimumUserModeAddress
                core::ptr::write(base.add(0x20).cast::<u64>(), 0x10000);
                // offset 0x28: MaximumUserModeAddress
                core::ptr::write(base.add(0x28).cast::<u64>(), 0x7FFF_FFFE_FFFF);
                // offset 0x30: ActiveProcessorsAffinityMask (4 CPUs)
                core::ptr::write(base.add(0x30).cast::<u64>(), 0xF);
                // offset 0x38: NumberOfProcessors
                core::ptr::write(base.add(0x38), 4);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, SBI_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemProcessorInformation (1)
        1 => {
            const SPI_SIZE: usize = 12;
            if (info_length as usize) < SPI_SIZE || info_ptr == 0 {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, SPI_SIZE as u32);
                    }
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, SPI_SIZE);
                let base = info_ptr as *mut u8;
                // ProcessorArchitecture at offset 0 (USHORT) — AMD64 = 9
                core::ptr::write(base.cast::<u16>(), 9);
                // ProcessorLevel at offset 2 (USHORT)
                core::ptr::write(base.add(2).cast::<u16>(), 6);
                // ProcessorRevision at offset 4 (USHORT)
                core::ptr::write(base.add(4).cast::<u16>(), 0x4E03);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, SPI_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemTimeOfDayInformation (3)
        3 => {
            // Minimal: return current time at offset 0.
            if (info_length as usize) < 8 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            let now = windows_filetime_now();
            unsafe {
                core::ptr::write_bytes(
                    info_ptr as *mut u8,
                    0,
                    core::cmp::min(info_length as usize, 48),
                );
                core::ptr::write(info_ptr as *mut i64, now);
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemRangeStartInformation (50)
        50 => {
            if (info_length as usize) < 8 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // Kernel range start on Windows x64.
            unsafe {
                core::ptr::write(info_ptr as *mut u64, 0xFFFF_8000_0000_0000);
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemBasicInformation extended (0x3E = 62). Same layout as class 0.
        0x3E => {
            const SBIE_SIZE: usize = 64;
            if (info_length as usize) < SBIE_SIZE || info_ptr == 0 {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, SBIE_SIZE as u32);
                    }
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, SBIE_SIZE);
                let base = info_ptr as *mut u8;
                // Same layout as class 0 (see comments there).
                core::ptr::write(base.add(0x04).cast::<u32>(), 156250);
                core::ptr::write(base.add(0x08).cast::<u32>(), 4096);
                core::ptr::write(base.add(0x0C).cast::<u32>(), 1048576);
                core::ptr::write(base.add(0x10).cast::<u32>(), 1);
                core::ptr::write(base.add(0x14).cast::<u32>(), 1048576);
                core::ptr::write(base.add(0x18).cast::<u32>(), 65536);
                core::ptr::write(base.add(0x20).cast::<u64>(), 0x10000);
                core::ptr::write(base.add(0x28).cast::<u64>(), 0x7FFF_FFFE_FFFF);
                core::ptr::write(base.add(0x30).cast::<u64>(), 0xF);
                core::ptr::write(base.add(0x38), 4);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, SBIE_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemProcessorGroupInformation (0x37 = 55). Returns per-group
        // processor info as PROCESSOR_GROUP_INFO entries (48 bytes each).
        // We report one group with 1 active processor.
        0x37 => {
            // PROCESSOR_GROUP_INFO layout (48 bytes):
            //   offset 0: MaximumProcessorCount (BYTE)
            //   offset 1: ActiveProcessorCount (BYTE)
            //   offset 2: Reserved[38] (BYTE[38])
            //   offset 40: ActiveProcessorMask (KAFFINITY = u64)
            const PGI_SIZE: usize = 48;
            if (info_length as usize) < PGI_SIZE || info_ptr == 0 {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, PGI_SIZE as u32);
                    }
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, PGI_SIZE);
                let base = info_ptr as *mut u8;
                // MaximumProcessorCount = 1
                core::ptr::write(base, 1u8);
                // ActiveProcessorCount = 1
                core::ptr::write(base.add(1), 1u8);
                // ActiveProcessorMask = 1 (bit 0 set)
                core::ptr::write(base.add(40).cast::<u64>(), 0x1);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, PGI_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemCodeIntegrityInformation (0xC0 = 192). ntdll checks CI flags.
        0xC0 => {
            const SCI_SIZE: usize = 8;
            if (info_length as usize) < SCI_SIZE || info_ptr == 0 {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, SCI_SIZE as u32);
                    }
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, SCI_SIZE);
                let base = info_ptr as *mut u8;
                // offset 0: Length (ULONG) = 8 (structure size)
                core::ptr::write(base.cast::<u32>(), SCI_SIZE as u32);
                // offset 4: CodeIntegrityOptions (ULONG) = 0x40
                core::ptr::write(base.add(4).cast::<u32>(), 0x40);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, SCI_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemHypervisorSharedPageInformation (0xC5 = 197). Returns a pointer to
        // the hypervisor shared page used for fast time queries. We allocate a page
        // in guest memory and return its address.
        0xC5 => {
            if (info_length as usize) < 8 || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            // Return 0 (no hypervisor shared page available). ntdll should
            // fall back to syscall-based time queries.
            unsafe {
                core::ptr::write(info_ptr as *mut u64, 0);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 8);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        _ => {
            // Unknown info class — many classes are queried during ntdll init.
            // Return zeroed data for reasonable buffer sizes to satisfy queries
            // we don't need to implement precisely (NUMA info, security, etc.).
            if info_ptr != 0 && info_length > 0 && info_length <= 0x10000 {
                unsafe {
                    core::ptr::write_bytes(info_ptr as *mut u8, 0, info_length as usize);
                }
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, info_length);
                    }
                }
                NtStatus::STATUS_SUCCESS
            } else {
                NtStatus::STATUS_INVALID_INFO_CLASS
            }
        }
    }
}

/// NtQuerySystemInformationEx — extended system information query.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQuerySystemInformationEx(
///     SYSTEM_INFORMATION_CLASS SystemInformationClass, // r10
///     PVOID InputBuffer,                               // rdx
///     ULONG InputBufferLength,                         // r8
///     PVOID SystemInformation,                         // r9
///     ULONG SystemInformationLength,                   // [rsp+0x28]
///     PULONG ReturnLength                              // [rsp+0x30]
/// );
/// ```
///
/// Called during ntdll init for NUMA/processor group and CPU set queries.
/// For class 0x6B (SystemCpuSetInformation), the caller does a two-step query:
/// first with output_len=0 to get the required size, then allocates and retries.
pub(crate) fn nt_query_system_information_ex(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let info_class = args.arg0 as u32;
    let info_ptr = args.arg3;
    let info_length = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const u32) };
    let return_length_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x30) as *const usize) };

    #[cfg(debug_assertions)]
    {
        use litebox::platform::DebugLogProvider as _;
        litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
            "  NtQuerySystemInformationEx: class=0x{info_class:X} out=0x{info_ptr:X} outLen={info_length} retLenPtr=0x{return_length_ptr:X}\n"
        ));
    }

    match info_class {
        // SystemLogicalProcessorAndGroupInformation (0x6B = 107).
        //
        // ntdll's LdrpInitializeProcess calls this with InputBuffer containing
        // a DWORD = 4 (RelationGroup) to discover the number of processor
        // groups. The caller does a two-step query:
        //   1. outBuf=NULL, outLen=0 → expect STATUS_INFO_LENGTH_MISMATCH + retLen
        //   2. allocate, retry → expect STATUS_SUCCESS + filled buffer
        //
        // If the returned MaximumGroupCount is 0, ntdll returns
        // STATUS_INTERNAL_ERROR and the process fails to start.
        //
        // We return a single SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX
        // (RelationGroup) with 1 active group containing 1 processor.
        //
        // Layout (80 bytes total):
        //   +0x00  DWORD Relationship = 4 (RelationGroup)
        //   +0x04  DWORD Size = 80
        //   +0x08  WORD  MaximumGroupCount = 1
        //   +0x0A  WORD  ActiveGroupCount = 1
        //   +0x0C  BYTE  Reserved[20] = {0}
        //   +0x20  PROCESSOR_GROUP_INFO[0]:
        //     +0x20  BYTE  MaximumProcessorCount = 1
        //     +0x21  BYTE  ActiveProcessorCount = 1
        //     +0x22  BYTE  Reserved[38] = {0}
        //     +0x48  KAFFINITY ActiveProcessorMask = 0x1
        0x6B => {
            const ENTRY_SIZE: u32 = 80;
            if info_ptr == 0 || info_length < ENTRY_SIZE {
                if return_length_ptr != 0 {
                    unsafe {
                        core::ptr::write(return_length_ptr as *mut u32, ENTRY_SIZE);
                    }
                }
                #[cfg(debug_assertions)]
                {
                    use litebox::platform::DebugLogProvider as _;
                    litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                        "  NtQuerySystemInformationEx(0x6B): buffer too small (ptr=0x{info_ptr:X} len={info_length}), returning INFO_LENGTH_MISMATCH\n"
                    ));
                }
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                let base = info_ptr as *mut u8;
                core::ptr::write_bytes(base, 0, ENTRY_SIZE as usize);
                // Relationship = RelationGroup (4)
                core::ptr::write(base.cast::<u32>(), 4);
                // Size
                core::ptr::write(base.add(4).cast::<u32>(), ENTRY_SIZE);
                // MaximumGroupCount
                core::ptr::write(base.add(8).cast::<u16>(), 1);
                // ActiveGroupCount
                core::ptr::write(base.add(10).cast::<u16>(), 1);
                // PROCESSOR_GROUP_INFO at offset 0x20:
                // MaximumProcessorCount
                core::ptr::write(base.add(0x20), 1);
                // ActiveProcessorCount
                core::ptr::write(base.add(0x21), 1);
                // ActiveProcessorMask (KAFFINITY = u64 at offset 0x48)
                core::ptr::write(base.add(0x48).cast::<u64>(), 0x1);
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, ENTRY_SIZE);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // SystemProcessorIdleCycleTimeInformation (0xD2) and
        // SystemProcessorCycleTimeInformation (0xD3): ntdll's loader queries
        // these during image mapping. Return SUCCESS with zeroed data so the
        // caller doesn't retry in an infinite loop. The output buffer is
        // already zeroed by the caller.
        0xD2 | 0xD3 => {
            // Zero the output buffer (may already be zero, but be safe).
            if info_ptr != 0 && info_length > 0 {
                unsafe {
                    core::ptr::write_bytes(info_ptr as *mut u8, 0, info_length as usize);
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, info_length);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // Default: unknown classes in NtQuerySystemInformationEx. The real
        // kernel returns STATUS_INFO_NOT_FOUND (0xC0000004) for unknown or
        // unsupported Ex classes. We must match this specific status code
        // because ntdll checks for it explicitly during init.
        _ => {
            #[cfg(debug_assertions)]
            {
                use litebox::platform::DebugLogProvider as _;
                litebox_platform_multiplex::platform().debug_log_print(&alloc::format!(
                    "  NtQuerySystemInformationEx: unknown class 0x{info_class:X} → STATUS_INFO_NOT_FOUND\n"
                ));
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 0);
                }
            }
            NtStatus(0xC0000004_u32 as i32) // STATUS_INFO_NOT_FOUND
        }
    }
}

/// NtQueryPerformanceCounter — high-resolution monotonic counter.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryPerformanceCounter(
///     PLARGE_INTEGER PerformanceCounter,  // r10
///     PLARGE_INTEGER PerformanceFrequency // rdx (optional)
/// );
/// ```
pub(crate) fn nt_query_performance_counter(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let counter_ptr = args.arg0;
    let frequency_ptr = args.arg1;

    if counter_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    // Use the platform's monotonic clock for the counter value.
    // On Windows, QPC frequency is typically 10 MHz.
    // We'll use a fixed 10 MHz frequency and derive the counter from
    // the current FILETIME (100ns intervals).
    const QPC_FREQUENCY: i64 = 10_000_000; // 10 MHz

    // Get current time as 100ns intervals since boot (approximation).
    // We use FILETIME as a monotonic-ish source. For proper monotonic
    // time, we'd use QueryPerformanceCounter, but from no_std we
    // approximate with system time.
    let now = windows_filetime_now();
    // Scale: FILETIME is 100ns units, QPC at 10MHz is also 100ns.
    let counter_value = now;

    unsafe {
        core::ptr::write(counter_ptr as *mut i64, counter_value);
    }

    if frequency_ptr != 0 {
        unsafe {
            core::ptr::write(frequency_ptr as *mut i64, QPC_FREQUENCY);
        }
    }

    NtStatus::STATUS_SUCCESS
}

/// NtQuerySystemTime — get the current UTC wall-clock time as FILETIME.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQuerySystemTime(
///     PLARGE_INTEGER SystemTime  // r10
/// );
/// ```
pub(crate) fn nt_query_system_time(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let time_ptr = args.arg0;

    if time_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let now = windows_filetime_now();
    unsafe {
        core::ptr::write(time_ptr as *mut i64, now);
    }

    NtStatus::STATUS_SUCCESS
}

/// NtQueryInformationProcess — query process information.
///
/// NT signature:
/// ```text
/// NTSTATUS NtQueryInformationProcess(
///     HANDLE ProcessHandle,                    // r10
///     PROCESSINFOCLASS ProcessInformationClass, // rdx
///     PVOID ProcessInformation,                // r8
///     ULONG ProcessInformationLength,          // r9
///     PULONG ReturnLength                      // [rsp+0x28]
/// );
/// ```
pub(crate) fn nt_query_information_process(
    ctx: &mut super::super::ExecutionContext,
    init_state: Option<&super::super::NtInitState>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let _handle = args.arg0;
    let info_class = args.arg1 as u32;
    let info_ptr = args.arg2;
    let info_length = args.arg3 as u32;

    let return_length_ptr = unsafe { core::ptr::read((ctx.regs.rsp + 0x28) as *const usize) };

    match info_class {
        // ProcessBasicInformation (0)
        0 => {
            // PROCESS_BASIC_INFORMATION: 48 bytes on x64
            const PBI_SIZE: usize = 48;
            if (info_length as usize) < PBI_SIZE || info_ptr == 0 {
                return NtStatus::STATUS_INFO_LENGTH_MISMATCH;
            }
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, PBI_SIZE);
                let base = info_ptr as *mut u8;
                // ExitStatus at offset 0 (NTSTATUS) — 0x103 = STATUS_PENDING
                core::ptr::write(base.cast::<u32>(), 0x103);
                // PebBaseAddress at offset 8 (PPEB)
                let peb_va = init_state.map_or(0usize, |s| s.peb_va);
                core::ptr::write(base.add(8).cast::<u64>(), peb_va as u64);
                // UniqueProcessId at offset 16 (ULONG_PTR)
                core::ptr::write(base.add(16).cast::<u64>(), 4); // fake PID
                // InheritedFromUniqueProcessId at offset 24 ... leave as 0
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, PBI_SIZE as u32);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessDebugPort (7) — no debugger attached.
        7 => {
            if info_ptr != 0 && info_length >= 8 {
                unsafe {
                    core::ptr::write(info_ptr as *mut u64, 0); // no debug port
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 8);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessDebugFlags (0x1F = 31)
        0x1F => {
            if info_ptr != 0 && info_length >= 4 {
                unsafe {
                    // 1 = PROCESS_DEBUG_INHERIT (not being debugged)
                    core::ptr::write(info_ptr as *mut u32, 1);
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 4);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessCookie (0x24 = 36) — returns a random non-zero u32 cookie
        36 => {
            if info_ptr != 0 && info_length >= 4 {
                unsafe {
                    // Return a fixed non-zero cookie value (real kernel returns random)
                    core::ptr::write(info_ptr as *mut u32, 0x5981937B_u32);
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 4);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessHandleCount (0x14 = 20)
        0x14 => {
            if info_ptr != 0 && info_length >= 4 {
                unsafe {
                    core::ptr::write(info_ptr as *mut u32, 16); // fake handle count
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 4);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessHandleCheckingMode (0x25 = 37) — return 0 (disabled)
        37 => {
            if info_ptr != 0 && info_length >= 4 {
                unsafe {
                    core::ptr::write(info_ptr as *mut u32, 0);
                }
            }
            if return_length_ptr != 0 {
                unsafe {
                    core::ptr::write(return_length_ptr as *mut u32, 4);
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessImageInformation (44) — return success with zeroed data.
        44 => {
            if info_ptr != 0 && info_length >= 8 {
                unsafe {
                    core::ptr::write_bytes(
                        info_ptr as *mut u8,
                        0,
                        core::cmp::min(info_length as usize, 64),
                    );
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        // ProcessMitigationPolicy (0x34 = 52) or (0x3F = 63)
        52 | 63 => {
            // Return zeroed data (no mitigations enabled).
            if info_ptr != 0 && info_length > 0 {
                unsafe {
                    core::ptr::write_bytes(
                        info_ptr as *mut u8,
                        0,
                        core::cmp::min(info_length as usize, 128),
                    );
                }
            }
            NtStatus::STATUS_SUCCESS
        }
        _ => NtStatus::STATUS_INVALID_INFO_CLASS,
    }
}

/// NtDelayExecution — sleep for a specified duration.
///
/// NT signature:
/// ```text
/// NTSTATUS NtDelayExecution(
///     BOOLEAN Alertable,       // r10
///     PLARGE_INTEGER DelayInterval // rdx
/// );
/// ```
///
/// DelayInterval is negative for relative time (in 100ns units).
pub(crate) fn nt_delay_execution(
    ctx: &mut super::super::ExecutionContext,
    wait_cx: &litebox::event::wait::WaitContext<'_, litebox_platform_multiplex::Platform>,
) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let delay_ptr = args.arg1;

    if delay_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let delay_100ns = unsafe { core::ptr::read(delay_ptr as *const i64) };

    // Negative = relative time in 100ns units.
    let sleep_us = match delay_100ns.cmp(&0) {
        core::cmp::Ordering::Less => delay_100ns.unsigned_abs() / 10,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 0,
    };

    if sleep_us > 0 {
        let timeout = core::time::Duration::from_micros(sleep_us);
        let cx = wait_cx.with_timeout(timeout);
        let _ = cx.sleep();
    } else {
        core::hint::spin_loop();
    }

    NtStatus::STATUS_SUCCESS
}

/// Get the current time as a Windows FILETIME value (100ns intervals since
/// 1601-01-01 00:00:00 UTC).
///
/// On Windows platforms, uses the real system time via GetSystemTimeAsFileTime.
/// On other platforms, returns a fixed epoch value.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn windows_filetime_now() -> i64 {
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    unsafe extern "system" {
        fn GetSystemTimeAsFileTime(ft: *mut FileTime);
    }

    let mut ft = FileTime { low: 0, high: 0 };
    unsafe {
        GetSystemTimeAsFileTime(&raw mut ft);
    }
    ((ft.high as i64) << 32) | (ft.low as i64)
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn windows_filetime_now() -> i64 {
    // Fallback: 2024-01-01 00:00:00 UTC in FILETIME units.
    133_475_136_000_000_000
}

/// Public wrapper for use by k32_handlers.
pub(crate) fn windows_filetime_now_pub() -> i64 {
    windows_filetime_now()
}

/// Read a high-resolution monotonic counter in nanoseconds (approximate).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn perf_counter_now() -> u64 {
    unsafe extern "system" {
        fn QueryPerformanceCounter(counter: *mut i64) -> i32;
        fn QueryPerformanceFrequency(freq: *mut i64) -> i32;
    }

    let mut counter: i64 = 0;
    let mut freq: i64 = 0;
    unsafe {
        QueryPerformanceCounter(&raw mut counter);
        QueryPerformanceFrequency(&raw mut freq);
    }
    if freq == 0 {
        return 0;
    }
    // Convert to nanoseconds: counter * 1_000_000_000 / freq
    // Use 128-bit math to avoid overflow.
    ((counter as u128 * 1_000_000_000) / freq as u128) as u64
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn perf_counter_now() -> u64 {
    0
}
