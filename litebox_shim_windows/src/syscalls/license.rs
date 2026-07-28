// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::UnicodeString;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_license_value(
        value_name: ConstPtr<Platform, UnicodeString>,
        _value_type: MutPtr<Platform, u32>,
        _data: MutPtr<Platform, u8>,
        _data_size: u32,
        result_data_size: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if value_name.as_usize() == 0 || result_data_size.as_usize() == 0 {
            return NtStatus::INVALID_PARAMETER;
        }
        let Some(value_name) = value_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if value_name.length == 0
            || !value_name.length.is_multiple_of(2)
            || value_name.maximum_length < value_name.length
            || value_name.buffer == 0
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if !value_name
            .buffer
            .is_multiple_of(core::mem::align_of::<u16>())
        {
            return NtStatus::DATATYPE_MISALIGNMENT;
        }
        let character_count = usize::from(value_name.length / 2);
        let Some(result_data_size_value) = result_data_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if ConstPtr::<Platform, u16>::from_usize(value_name.buffer)
            .to_owned_slice(character_count)
            .is_none()
            || result_data_size
                .write_at_offset(0, result_data_size_value)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        // TODO(license-store): Report every policy as absent until LiteBox has a license store.
        NtStatus::OBJECT_NAME_NOT_FOUND
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{const_ptr, mut_byte_ptr, mut_ptr, null_const_ptr, null_mut_ptr};
    use litebox::platform::ThreadProvider;

    type TestPlatform = crate::tests::TestPlatform;
    type TestTask = Task<TestPlatform, crate::tests::TestFS>;

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn value_name(buffer: &[u16]) -> UnicodeString {
        UnicodeString {
            length: u16::try_from(core::mem::size_of_val(buffer)).unwrap(),
            maximum_length: u16::try_from(core::mem::size_of_val(buffer)).unwrap(),
            padding_0: [0; 4],
            buffer: buffer.as_ptr() as usize,
        }
    }

    #[test]
    fn nt_query_license_value_rejects_null_value_name() {
        run_with_test_platform_pointers(|| {
            let mut result_data_size = u32::MAX;

            assert_eq!(
                TestTask::sys_nt_query_license_value(
                    null_const_ptr(),
                    null_mut_ptr(),
                    null_mut_ptr(),
                    0,
                    mut_ptr(&mut result_data_size),
                ),
                NtStatus::INVALID_PARAMETER
            );
            assert_eq!(result_data_size, u32::MAX);
        });
    }

    #[test]
    fn nt_query_license_value_reports_unknown_values_without_clobbering_outputs() {
        run_with_test_platform_pointers(|| {
            let value_name_buffer = [u16::from(b'x')];
            let value_name = value_name(&value_name_buffer);
            let mut value_type = u32::MAX;
            let mut data = u8::MAX;
            let mut result_data_size = u32::MAX;

            assert_eq!(
                TestTask::sys_nt_query_license_value(
                    const_ptr(&value_name),
                    mut_ptr(&mut value_type),
                    mut_byte_ptr(&mut data),
                    1,
                    mut_ptr(&mut result_data_size),
                ),
                NtStatus::OBJECT_NAME_NOT_FOUND
            );
            assert_eq!(result_data_size, u32::MAX);
            assert_eq!(value_type, u32::MAX);
            assert_eq!(data, u8::MAX);
        });
    }

    #[test]
    fn nt_query_license_value_validates_name_and_result_size() {
        run_with_test_platform_pointers(|| {
            let value_name_buffer = [u16::from(b'x')];
            let value_name = value_name(&value_name_buffer);

            assert_eq!(
                TestTask::sys_nt_query_license_value(
                    const_ptr(&value_name),
                    null_mut_ptr(),
                    null_mut_ptr(),
                    0,
                    null_mut_ptr(),
                ),
                NtStatus::INVALID_PARAMETER
            );

            let mut result_data_size = u32::MAX;
            for invalid_name in [
                UnicodeString {
                    length: 0,
                    maximum_length: 0,
                    padding_0: [0; 4],
                    buffer: 0,
                },
                UnicodeString {
                    length: 1,
                    maximum_length: 2,
                    padding_0: [0; 4],
                    buffer: value_name_buffer.as_ptr() as usize,
                },
                UnicodeString {
                    length: 2,
                    maximum_length: 0,
                    padding_0: [0; 4],
                    buffer: value_name_buffer.as_ptr() as usize,
                },
                UnicodeString {
                    length: 2,
                    maximum_length: 2,
                    padding_0: [0; 4],
                    buffer: 0,
                },
            ] {
                assert_eq!(
                    TestTask::sys_nt_query_license_value(
                        const_ptr(&invalid_name),
                        null_mut_ptr(),
                        null_mut_ptr(),
                        0,
                        mut_ptr(&mut result_data_size),
                    ),
                    NtStatus::INVALID_PARAMETER
                );
            }

            let invalid_name = UnicodeString {
                length: 2,
                maximum_length: 2,
                padding_0: [0; 4],
                buffer: usize::MAX & !1,
            };
            assert_eq!(
                TestTask::sys_nt_query_license_value(
                    const_ptr(&invalid_name),
                    null_mut_ptr(),
                    null_mut_ptr(),
                    0,
                    mut_ptr(&mut result_data_size),
                ),
                NtStatus::ACCESS_VIOLATION
            );

            let name_storage = [0u8; 4];
            let misaligned_name = UnicodeString {
                length: 2,
                maximum_length: 2,
                padding_0: [0; 4],
                buffer: name_storage.as_ptr() as usize + 1,
            };
            assert_eq!(
                TestTask::sys_nt_query_license_value(
                    const_ptr(&misaligned_name),
                    null_mut_ptr(),
                    null_mut_ptr(),
                    0,
                    mut_ptr(&mut result_data_size),
                ),
                NtStatus::DATATYPE_MISALIGNMENT
            );
        });
    }
}
