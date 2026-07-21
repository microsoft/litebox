// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::Guid;
use crate::{
    ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_buffer,
    probe_guest_output_preserving_value,
};

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
        let outputs_valid = probe_guest_output_preserving_value::<Platform, u32>(change_stamp)
            .is_ok()
            && probe_guest_output_preserving_value::<Platform, u32>(buffer_size).is_ok()
            && probe_guest_output_buffer::<Platform>(buffer, available_size as usize).is_ok();
        if !outputs_valid {
            return NtStatus::ACCESS_VIOLATION;
        }
        if explicit_scope.is_some() {
            // TODO(wnf-explicit-scope): Key state data by the explicit SID once scoped WNF state
            // creation and security checks are modeled.
            litebox_util_log::debug!(
                state_name:% = format_args!("{state_name:#x}");
                "Explicit-scope WNF state queries are not supported"
            );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestFS, TestPlatform, mut_byte_ptr, mut_ptr, test_task};

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
