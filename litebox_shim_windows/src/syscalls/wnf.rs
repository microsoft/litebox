// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::Guid;
use crate::{ConstPtr, MutPtr, ShimFS, ShimPlatform, Task};

#[derive(Clone)]
pub(crate) struct WnfStateData {
    change_stamp: u32,
    type_id: Option<Guid>,
    data: Vec<u8>,
}

pub(crate) type WnfStateStore<Platform> =
    litebox::sync::RwLock<Platform, BTreeMap<u64, WnfStateData>>;

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_query_wnf_state_data(
        &self,
        state_name: ConstPtr<Platform, u64>,
        type_id: Option<ConstPtr<Platform, Guid>>,
        explicit_scope: Option<ConstPtr<Platform, u8>>,
        change_stamp: MutPtr<Platform, u32>,
        buffer: MutPtr<Platform, u8>,
        buffer_size: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let Some(state_name) = state_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let type_id = match type_id {
            Some(type_id) => match type_id.read_at_offset(0) {
                Some(type_id) => Some(type_id),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };
        let Some(available_size) = buffer_size.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let outputs_valid = change_stamp
            .read_at_offset(0)
            .and_then(|value| change_stamp.write_at_offset(0, value))
            .is_some()
            && buffer_size.write_at_offset(0, available_size).is_some()
            && probe_output_buffer::<Platform>(buffer, available_size as usize).is_ok();
        if !outputs_valid {
            return NtStatus::ACCESS_VIOLATION;
        }
        if explicit_scope.is_some() {
            // TODO(wnf-explicit-scope): Key state data by the explicit SID once scoped WNF state
            // creation and security checks are modeled.
            return NtStatus::INVALID_PARAMETER;
        }

        let state = {
            let states = self.global.wnf_states.read();
            states.get(&state_name).cloned()
        };
        let Some(state) = state else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        if let (Some(type_id), Some(expected_type_id)) = (type_id, state.type_id)
            && type_id.data != expected_type_id.data
        {
            return NtStatus::OBJECT_TYPE_MISMATCH;
        }

        let Ok(required_size) = u32::try_from(state.data.len()) else {
            return NtStatus::BUFFER_OVERFLOW;
        };
        if available_size < required_size {
            if change_stamp
                .write_at_offset(0, state.change_stamp)
                .is_none()
                || buffer_size.write_at_offset(0, required_size).is_none()
            {
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::BUFFER_TOO_SMALL;
        }

        if !state.data.is_empty() && buffer.write_slice_at_offset(0, &state.data).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if change_stamp
            .write_at_offset(0, state.change_stamp)
            .is_none()
            || buffer_size.write_at_offset(0, required_size).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }
}

fn probe_output_buffer<Platform: ShimPlatform>(
    buffer: MutPtr<Platform, u8>,
    buffer_size: usize,
) -> Result<(), NtStatus> {
    if buffer_size == 0 {
        return Ok(());
    }
    let first = buffer.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION)?;
    buffer
        .write_at_offset(0, first)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    let last_offset = isize::try_from(buffer_size - 1).map_err(|_| NtStatus::ACCESS_VIOLATION)?;
    let last = buffer
        .read_at_offset(last_offset)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    buffer
        .write_at_offset(last_offset, last)
        .ok_or(NtStatus::ACCESS_VIOLATION)
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use litebox::platform::ThreadProvider;

    use super::*;
    use crate::tests::{
        TestFS, TestPlatform, mut_byte_ptr, mut_ptr, null_mut_ptr, test_platform, test_task,
    };

    const STATE_NAME: u64 = 0x41c6_4e6d_a3bc_0075;

    fn publish_state(
        task: &Task<TestPlatform, TestFS>,
        change_stamp: u32,
        type_id: Option<Guid>,
        data: &[u8],
    ) {
        task.global.wnf_states.write().insert(
            STATE_NAME,
            WnfStateData {
                change_stamp,
                type_id,
                data: data.into(),
            },
        );
    }

    fn task_with_new_process(task: &Task<TestPlatform, TestFS>) -> Task<TestPlatform, TestFS> {
        Task {
            global: task.global.clone(),
            process: Arc::new(crate::Process::default(
                None,
                task.process.windows_shared_section.clone(),
            )),
            fs: task.fs.clone(),
            entry_point: task.entry_point,
            stack_top: task.stack_top,
            context: task.context,
            teb_address: task.teb_address,
        }
    }

    #[test]
    fn query_shares_state_data_across_processes() {
        let publisher = test_task();
        publish_state(&publisher, 7, None, &[1, 2, 3, 4]);
        let subscriber = task_with_new_process(&publisher);
        let state_name = STATE_NAME;
        let mut change_stamp = 0;
        let mut buffer = [0xaau8; 8];
        let mut buffer_size = 8;

        assert_eq!(
            subscriber.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(change_stamp, 7);
        assert_eq!(buffer_size, 4);
        assert_eq!(&buffer, &[1, 2, 3, 4, 0xaa, 0xaa, 0xaa, 0xaa]);
    }

    #[test]
    fn empty_state_allows_a_null_buffer() {
        let task = test_task();
        publish_state(&task, 3, None, &[]);
        let state_name = STATE_NAME;
        let mut change_stamp = 0;
        let mut buffer_size = 0;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                null_mut_ptr(),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(change_stamp, 3);
        assert_eq!(buffer_size, 0);
    }

    #[test]
    fn undersized_query_reports_change_stamp_and_required_size() {
        let task = test_task();
        publish_state(&task, 7, None, &[1, 2, 3, 4]);
        let state_name = STATE_NAME;
        let mut change_stamp = 99;
        let mut buffer = [0xaau8; 4];
        let mut buffer_size = 2;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(buffer_size, 4);
        assert_eq!(change_stamp, 7);
        assert_eq!(buffer, [0xaa; 4]);
    }

    #[test]
    fn unknown_state_leaves_outputs_unchanged() {
        let task = test_task();
        let state_name = STATE_NAME;
        let mut change_stamp = 99;
        let mut buffer = [0xaau8; 4];
        let mut buffer_size = 4;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(buffer_size, 4);
        assert_eq!(change_stamp, 99);
        assert_eq!(buffer, [0xaa; 4]);
    }

    #[test]
    fn query_validates_optional_type_id() {
        let task = test_task();
        let expected_type = Guid { data: [1; 16] };
        publish_state(&task, 7, Some(expected_type), &[1]);
        let state_name = STATE_NAME;
        let wrong_type = Guid { data: [2; 16] };
        let mut change_stamp = 99;
        let mut buffer = [0xaau8; 1];
        let mut buffer_size = 1;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                Some(crate::tests::const_ptr(&wrong_type)),
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(buffer_size, 1);
        assert_eq!(change_stamp, 99);
        assert_eq!(buffer, [0xaa; 1]);
    }

    #[test]
    fn untyped_state_accepts_an_optional_type_id() {
        let task = test_task();
        publish_state(&task, 7, None, &[1]);
        let state_name = STATE_NAME;
        let type_id = Guid { data: [2; 16] };
        let mut change_stamp = 0;
        let mut buffer = [0u8; 1];
        let mut buffer_size = 1;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                Some(crate::tests::const_ptr(&type_id)),
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(change_stamp, 7);
        assert_eq!(buffer_size, 1);
        assert_eq!(buffer, [1]);
    }

    #[test]
    fn query_probes_the_supplied_buffer_before_state_lookup() {
        let _ = test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(|| {
            let task = test_task();
            let state_name = STATE_NAME;
            let mut change_stamp = 99;
            let mut buffer_size = 1;

            assert_eq!(
                task.sys_nt_query_wnf_state_data(
                    crate::tests::const_ptr(&state_name),
                    None,
                    None,
                    mut_ptr(&mut change_stamp),
                    null_mut_ptr(),
                    mut_ptr(&mut buffer_size),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(change_stamp, 99);
            assert_eq!(buffer_size, 1);
        });
    }

    #[test]
    fn explicit_scope_is_rejected_until_scoped_states_are_modeled() {
        let task = test_task();
        let state_name = STATE_NAME;
        let explicit_scope = 0u8;
        let mut change_stamp = 99;
        let mut buffer = [0xaau8; 1];
        let mut buffer_size = 1;

        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                crate::tests::const_ptr(&state_name),
                None,
                Some(crate::tests::const_ptr(&explicit_scope)),
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(change_stamp, 99);
        assert_eq!(buffer_size, 1);
        assert_eq!(buffer, [0xaa; 1]);
    }
}
