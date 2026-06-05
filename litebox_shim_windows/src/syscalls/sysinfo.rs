// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::{Instant as _, RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

const QPC_FREQUENCY_HZ: i64 = 1_000_000_000;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_performance_counter(
        &self,
        performance_counter: MutPtr<Platform, i64>,
        performance_frequency: Option<MutPtr<Platform, i64>>,
    ) -> NtStatus {
        let elapsed = self
            .global
            .platform
            .now()
            .duration_since(&self.global.qpc_boot_instant);
        let ticks = duration_as_qpc_ticks(elapsed);

        if performance_counter.write_at_offset(0, ticks).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(performance_frequency) = performance_frequency
            && performance_frequency
                .write_at_offset(0, QPC_FREQUENCY_HZ)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        litebox_util_log::debug!(
            performance_counter = ticks,
            performance_frequency = QPC_FREQUENCY_HZ;
            "Handled NtQueryPerformanceCounter syscall"
        );
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_convert_between_auxiliary_counter_and_performance_counter(
        _flag: u32,
        source: ConstPtr<Platform, u64>,
        _destination: MutPtr<Platform, u64>,
        _conversion_error: Option<MutPtr<Platform, u64>>,
    ) -> NtStatus {
        if source.as_usize() == 0 {
            return NtStatus::ACCESS_VIOLATION;
        }

        // Wine reports auxiliary counter conversion as unsupported after validating the source.
        NtStatus::NOT_SUPPORTED
    }
}

fn duration_as_qpc_ticks(duration: core::time::Duration) -> i64 {
    i64::try_from(core::cmp::min(duration.as_nanos(), i64::MAX as u128)).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{const_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use core::time::Duration;
    use litebox::platform::ThreadProvider;

    extern crate std;

    const QPC_SLEEP_DURATION: Duration = Duration::from_millis(25);
    const QPC_SLEEP_TOLERANCE: Duration = Duration::from_millis(10);

    type TestPlatform = crate::tests::TestPlatform;

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    unsafe extern "system" {
        fn NtQueryPerformanceCounter(counter: *mut i64, frequency: *mut i64) -> i32;

        fn NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
            flag: u32,
            source: *const u64,
            destination: *mut u64,
            conversion_error: *mut u64,
        ) -> i32;
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn sys_nt_convert_between_auxiliary_counter_and_performance_counter(
        flag: u32,
        source: ConstPtr<TestPlatform, u64>,
        destination: MutPtr<TestPlatform, u64>,
        conversion_error: Option<MutPtr<TestPlatform, u64>>,
    ) -> NtStatus {
        Task::<TestPlatform, crate::tests::TestFS>::sys_nt_convert_between_auxiliary_counter_and_performance_counter(
            flag,
            source,
            destination,
            conversion_error,
        )
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    fn host_status(status: i32) -> NtStatus {
        NtStatus::from_raw(u32::from_ne_bytes(status.to_ne_bytes()))
    }

    fn qpc_delta_nanos(start: i64, end: i64) -> u128 {
        assert!(end >= start);
        u128::try_from(end - start).unwrap()
    }

    #[test]
    fn nt_query_performance_counter_writes_monotonic_counter_and_frequency() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut first_counter = -1i64;
            let mut second_counter = -1i64;
            let mut frequency = 0i64;

            assert_eq!(
                task.sys_nt_query_performance_counter(
                    mut_ptr(&mut first_counter),
                    Some(mut_ptr(&mut frequency)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(frequency, QPC_FREQUENCY_HZ);
            assert!(first_counter >= 0);

            assert_eq!(
                task.sys_nt_query_performance_counter(mut_ptr(&mut second_counter), None),
                NtStatus::SUCCESS
            );
            assert!(second_counter >= first_counter);
        });
    }

    #[test]
    fn nt_query_performance_counter_rejects_null_counter() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut frequency = 0i64;

            assert_eq!(
                task.sys_nt_query_performance_counter(
                    null_mut_ptr(),
                    Some(mut_ptr(&mut frequency)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn nt_convert_between_auxiliary_counter_and_performance_counter_is_not_supported() {
        run_with_test_platform_pointers(|| {
            let source = 0u64;
            let mut destination = 0u64;
            let mut conversion_error = 0u64;

            assert_eq!(
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    null_const_ptr(),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    const_ptr(&source),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                ),
                NtStatus::NOT_SUPPORTED
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_query_performance_counter_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut host_counter = 0i64;
            let mut host_frequency = 0i64;
            let mut guest_counter = 0i64;
            let mut guest_frequency = 0i64;

            // SAFETY: This Windows-only test calls the process ntdll export with valid local
            // output pointers and checks only the returned status and written scalar values.
            let host_valid_status = unsafe {
                host_status(NtQueryPerformanceCounter(
                    &raw mut host_counter,
                    &raw mut host_frequency,
                ))
            };
            let guest_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_counter),
                Some(mut_ptr(&mut guest_frequency)),
            );

            assert_eq!(guest_status, host_valid_status);
            assert!(guest_counter >= 0);
            assert!(guest_frequency > 0);
            assert!(host_counter >= 0);
            assert!(host_frequency > 0);

            // SAFETY: Passing a null counter pointer intentionally probes host ntdll's invalid
            // output behavior; the non-null frequency pointer is a valid local output.
            let host_null_counter_status = unsafe {
                host_status(NtQueryPerformanceCounter(
                    core::ptr::null_mut(),
                    &raw mut host_frequency,
                ))
            };
            let guest_null_counter_status = task.sys_nt_query_performance_counter(
                null_mut_ptr(),
                Some(mut_ptr(&mut guest_frequency)),
            );
            assert_eq!(guest_null_counter_status, host_null_counter_status);
        });
    }

    #[test]
    fn nt_query_performance_counter_duration_tracks_sleep_duration() {
        run_with_test_platform_pointers(|| {
            let task = crate::tests::test_task();
            let mut guest_frequency = 0i64;
            let mut guest_start = 0i64;
            let mut guest_end = 0i64;

            let guest_start_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_start),
                Some(mut_ptr(&mut guest_frequency)),
            );

            std::thread::sleep(QPC_SLEEP_DURATION);

            let guest_end_status = task.sys_nt_query_performance_counter(
                mut_ptr(&mut guest_end),
                Some(mut_ptr(&mut guest_frequency)),
            );

            assert_eq!(guest_start_status, NtStatus::SUCCESS);
            assert_eq!(guest_end_status, NtStatus::SUCCESS);
            assert_eq!(guest_frequency, QPC_FREQUENCY_HZ);

            let guest_duration_nanos = qpc_delta_nanos(guest_start, guest_end);
            let minimum_duration_nanos = QPC_SLEEP_DURATION
                .saturating_sub(QPC_SLEEP_TOLERANCE)
                .as_nanos();
            let maximum_duration_nanos = QPC_SLEEP_DURATION
                .saturating_add(QPC_SLEEP_TOLERANCE)
                .as_nanos();

            assert!(
                guest_duration_nanos >= minimum_duration_nanos,
                "guest duration {guest_duration_nanos}ns was shorter than requested sleep minus tolerance {minimum_duration_nanos}ns",
            );
            assert!(
                guest_duration_nanos <= maximum_duration_nanos,
                "guest duration {guest_duration_nanos}ns was longer than requested sleep plus tolerance {maximum_duration_nanos}ns",
            );
        });
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn nt_convert_between_auxiliary_counter_status_matches_host_ntdll() {
        run_with_test_platform_pointers(|| {
            let source = 0u64;
            let mut destination = 0u64;
            let mut conversion_error = 0u64;

            // SAFETY: Passing a null source pointer intentionally probes host ntdll's invalid
            // input behavior; the output pointers are valid local scalars for the duration.
            let host_null_source_status = unsafe {
                host_status(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                    0,
                    core::ptr::null(),
                    &raw mut destination,
                    &raw mut conversion_error,
                ))
            };
            let guest_null_source_status =
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    null_const_ptr(),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                );
            assert_eq!(guest_null_source_status, host_null_source_status);

            // SAFETY: All pointers passed to host ntdll point at local scalar variables that live
            // for the whole call; the function does not retain them.
            let host_valid_source_status = unsafe {
                host_status(NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
                    0,
                    &raw const source,
                    &raw mut destination,
                    &raw mut conversion_error,
                ))
            };
            let guest_valid_source_status =
                sys_nt_convert_between_auxiliary_counter_and_performance_counter(
                    0,
                    const_ptr(&source),
                    mut_ptr(&mut destination),
                    Some(mut_ptr(&mut conversion_error)),
                );
            assert_eq!(guest_valid_source_status, host_valid_source_status);
        });
    }
}
