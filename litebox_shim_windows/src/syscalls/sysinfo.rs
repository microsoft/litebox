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
            unsafe {
                core::ptr::write_bytes(info_ptr as *mut u8, 0, SBI_SIZE);
                let base = info_ptr as *mut u8;
                // TimerResolution at offset 0 (ULONG) — 100ns units, ~15.6ms
                core::ptr::write(base.cast::<u32>(), 156250);
                // PageSize at offset 4 (ULONG)
                core::ptr::write(base.add(4).cast::<u32>(), 4096);
                // NumberOfPhysicalPages at offset 8 (ULONG)
                core::ptr::write(base.add(8).cast::<u32>(), 1048576); // ~4GB
                // LowestPhysicalPageNumber at offset 12 (ULONG)
                core::ptr::write(base.add(12).cast::<u32>(), 1);
                // HighestPhysicalPageNumber at offset 16 (ULONG)
                core::ptr::write(base.add(16).cast::<u32>(), 1048576);
                // AllocationGranularity at offset 20 (ULONG)
                core::ptr::write(base.add(20).cast::<u32>(), 65536);
                // MinimumUserModeAddress at offset 24 (ULONG_PTR)
                core::ptr::write(base.add(24).cast::<u64>(), 0x10000);
                // MaximumUserModeAddress at offset 32 (ULONG_PTR)
                core::ptr::write(base.add(32).cast::<u64>(), 0x7FFFFFFEFFFF);
                // ActiveProcessorsAffinityMask at offset 40 (KAFFINITY)
                core::ptr::write(base.add(40).cast::<u64>(), 1);
                // NumberOfProcessors at offset 48 (CCHAR)
                core::ptr::write(base.add(48), 1);
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
        _ => {
            // Unknown info class — return not-implemented so the CRT can
            // fall back.
            NtStatus::STATUS_INVALID_INFO_CLASS
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
pub(crate) fn nt_delay_execution(ctx: &mut super::super::ExecutionContext) -> NtStatus {
    let args = NtSyscallArgs::from_ctx(ctx);
    let delay_ptr = args.arg1;

    if delay_ptr == 0 {
        return NtStatus::STATUS_ACCESS_VIOLATION;
    }

    let delay_100ns = unsafe { core::ptr::read(delay_ptr as *const i64) };

    // Negative = relative time. Convert to microseconds for the platform sleep.
    let sleep_us = if delay_100ns < 0 {
        // Absolute value, convert 100ns -> us (divide by 10).
        ((-delay_100ns) / 10) as u64
    } else if delay_100ns == 0 {
        // Zero means yield.
        0
    } else {
        // Positive = absolute time. Sleep until then.
        let now = windows_filetime_now();
        let diff = delay_100ns - now;
        if diff <= 0 { 0 } else { (diff / 10) as u64 }
    };

    if sleep_us > 0 {
        // Use platform hint_spin_loop as a crude sleep for very short delays,
        // or the real sleep path. For now, a simple busy-wait for short sleeps
        // and yield for zero-length delays.
        // TODO: Use a proper platform sleep primitive in Phase 3.
        let sleep_ns = sleep_us * 1000;
        let start = perf_counter_now();
        while (perf_counter_now() - start) < sleep_ns {
            core::hint::spin_loop();
        }
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
