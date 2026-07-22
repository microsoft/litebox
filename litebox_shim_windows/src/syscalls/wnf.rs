// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::Guid;
use crate::{
    ConstPtr, MutPtr, ShimFS, ShimPlatform, Task, probe_guest_output_buffer,
    probe_guest_output_preserving_value,
};

const MAXIMUM_STATE_SIZE: u32 = 0x1000;
const STATE_NAME_XOR_KEY: u64 = 0x41c6_4e6d_a3bc_0074;
const MAXIMUM_UNIQUE_ID: u32 = 0x001f_ffff;
const STATE_NAME_INFORMATION_SIZE: u32 = 4;
const INITIAL_CHANGE_STAMP: u32 = 0;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum WnfStateNameLifetime {
    WellKnown = 0,
    Permanent = 1,
    Persistent = 2,
    Temporary = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum WnfDataScope {
    System = 0,
    Session = 1,
    User = 2,
    Process = 3,
    Machine = 4,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum WnfStateNameInformation {
    Exists = 0,
    SubscribersPresent = 1,
    IsQuiescent = 2,
}

#[derive(Clone)]
pub(crate) struct WnfStateData {
    change_stamp: u32,
    type_id: Option<Guid>,
    data: Vec<u8>,
    maximum_state_size: u32,
    lifetime: WnfStateNameLifetime,
}

#[derive(Default)]
pub(crate) struct WnfStateStoreData {
    next_unique_id: u32,
    states: BTreeMap<u64, WnfStateData>,
}

pub(crate) type WnfStateStore<Platform> = litebox::sync::RwLock<Platform, WnfStateStoreData>;

pub(crate) struct WnfCreateStateNameParameters<Platform: litebox::platform::RawPointerProvider> {
    pub(crate) state_name: MutPtr<Platform, u64>,
    pub(crate) name_lifetime: u32,
    pub(crate) data_scope: u32,
    pub(crate) persist_data: u8,
    pub(crate) type_id: Option<ConstPtr<Platform, Guid>>,
    pub(crate) maximum_state_size: u32,
    pub(crate) security_descriptor: ConstPtr<Platform, u8>,
}

pub(crate) struct WnfUpdateStateDataParameters<Platform: litebox::platform::RawPointerProvider> {
    pub(crate) state_name: ConstPtr<Platform, u64>,
    pub(crate) buffer: Option<ConstPtr<Platform, u8>>,
    pub(crate) buffer_size: u32,
    pub(crate) type_id: Option<ConstPtr<Platform, Guid>>,
    pub(crate) explicit_scope: Option<ConstPtr<Platform, u8>>,
    pub(crate) matching_change_stamp: u32,
    pub(crate) check_stamp: i32,
}

impl<Platform: ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_create_wnf_state_name(
        &self,
        params: WnfCreateStateNameParameters<Platform>,
    ) -> NtStatus {
        if probe_guest_output_preserving_value::<Platform, u64>(params.state_name).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let type_id = match read_type_id::<Platform>(params.type_id) {
            Ok(type_id) => type_id,
            Err(status) => return status,
        };
        if params.security_descriptor.read_at_offset(0).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        let Ok(lifetime) = WnfStateNameLifetime::try_from(params.name_lifetime) else {
            return NtStatus::INVALID_PARAMETER;
        };
        let Ok(data_scope) = WnfDataScope::try_from(params.data_scope) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if params.maximum_state_size > MAXIMUM_STATE_SIZE {
            return NtStatus::INVALID_PARAMETER;
        }
        match lifetime {
            WnfStateNameLifetime::WellKnown => return NtStatus::INVALID_PARAMETER,
            WnfStateNameLifetime::Permanent | WnfStateNameLifetime::Persistent => {
                // TODO(wnf-create-privilege): Allow privileged lifetimes once guest token
                // privileges are modeled.
                return NtStatus::PRIVILEGE_NOT_HELD;
            }
            WnfStateNameLifetime::Temporary => {}
        }
        if data_scope == WnfDataScope::Process || params.persist_data != 0 {
            return NtStatus::INVALID_PARAMETER;
        }

        // TODO(wnf-security-descriptor): Enforce the supplied DACL once guest tokens and WNF
        // access checks are modeled.
        let state_name = {
            let mut store = self.global.wnf_states.write();
            let Some(unique_id) = store.next_unique_id.checked_add(1) else {
                return NtStatus::NO_MEMORY;
            };
            if unique_id > MAXIMUM_UNIQUE_ID {
                return NtStatus::NO_MEMORY;
            }
            store.next_unique_id = unique_id;
            let state_name = encode_state_name(lifetime, data_scope, false, unique_id);
            let state = WnfStateData {
                change_stamp: INITIAL_CHANGE_STAMP,
                type_id,
                data: Vec::new(),
                maximum_state_size: params.maximum_state_size,
                lifetime,
            };
            // TODO(wnf-temporary-lifetime): Remove temporary names when their creating guest
            // process exits once process lifecycle is modeled.
            store.states.insert(state_name, state);
            state_name
        };
        if params.state_name.write_at_offset(0, state_name).is_none() {
            let mut store = self.global.wnf_states.write();
            if store
                .states
                .get(&state_name)
                .is_some_and(|current| current.change_stamp == INITIAL_CHANGE_STAMP)
            {
                store.states.remove(&state_name);
            }
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_update_wnf_state_data(
        &self,
        params: WnfUpdateStateDataParameters<Platform>,
    ) -> NtStatus {
        let Some(state_name) = params.state_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let type_id = match read_type_id::<Platform>(params.type_id) {
            Ok(type_id) => type_id,
            Err(status) => return status,
        };
        if params.explicit_scope.is_some() {
            // TODO(wnf-explicit-scope): Key state data by the explicit SID once scoped WNF
            // state access is modeled.
            return NtStatus::INVALID_PARAMETER;
        }
        let data = if params.buffer_size == 0 {
            Vec::new()
        } else {
            let Some(buffer) = params.buffer else {
                return NtStatus::ACCESS_VIOLATION;
            };
            let Some(data) = buffer.to_owned_slice(params.buffer_size as usize) else {
                return NtStatus::ACCESS_VIOLATION;
            };
            Vec::from(data)
        };

        let mut store = self.global.wnf_states.write();
        let Some(state) = store.states.get_mut(&state_name) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        if !type_id_matches(state.type_id, type_id) || params.buffer_size > state.maximum_state_size
        {
            return NtStatus::INVALID_PARAMETER;
        }
        if params.check_stamp != 0 && params.matching_change_stamp != state.change_stamp {
            return NtStatus::UNSUCCESSFUL;
        }
        state.change_stamp = state.change_stamp.wrapping_add(1);
        state.data = data;
        // TODO(wnf-notify): Deliver successful updates to subscribers when WNF subscriptions are
        // modeled.
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_delete_wnf_state_data(
        &self,
        state_name: ConstPtr<Platform, u64>,
        explicit_scope: Option<ConstPtr<Platform, u8>>,
    ) -> NtStatus {
        let Some(state_name) = state_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        if explicit_scope.is_some() {
            // TODO(wnf-explicit-scope): Delete only the selected SID-scoped data instance once
            // scoped WNF state access is modeled.
            return NtStatus::INVALID_PARAMETER;
        }
        let mut store = self.global.wnf_states.write();
        let Some(state) = store.states.get_mut(&state_name) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        state.change_stamp = 0;
        state.data.clear();
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_delete_wnf_state_name(
        &self,
        state_name: ConstPtr<Platform, u64>,
    ) -> NtStatus {
        let Some(state_name) = state_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let mut store = self.global.wnf_states.write();
        let Some(state) = store.states.get(&state_name) else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        if state.lifetime == WnfStateNameLifetime::WellKnown {
            return NtStatus::INVALID_PARAMETER;
        }
        store.states.remove(&state_name);
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_wnf_state_name_information(
        &self,
        state_name: ConstPtr<Platform, u64>,
        name_information_class: u32,
        explicit_scope: Option<ConstPtr<Platform, u8>>,
        buffer: MutPtr<Platform, u32>,
        buffer_size: u32,
    ) -> NtStatus {
        let Some(state_name) = state_name.read_at_offset(0) else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let Ok(information_class) = WnfStateNameInformation::try_from(name_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if buffer_size != STATE_NAME_INFORMATION_SIZE {
            return NtStatus::INVALID_PARAMETER;
        }
        if explicit_scope.is_some() {
            // TODO(wnf-explicit-scope): Resolve the selected SID-scoped state instance once scoped
            // WNF state access is modeled.
            return NtStatus::INVALID_PARAMETER;
        }
        if probe_guest_output_preserving_value::<Platform, u32>(buffer).is_err() {
            return NtStatus::ACCESS_VIOLATION;
        }

        let store = self.global.wnf_states.read();
        let exists = store.states.contains_key(&state_name);
        let value = match information_class {
            WnfStateNameInformation::Exists => u32::from(exists),
            WnfStateNameInformation::SubscribersPresent => {
                if !exists {
                    return NtStatus::OBJECT_NAME_NOT_FOUND;
                }
                // TODO(wnf-notify): Report registered subscribers once WNF subscriptions are
                // modeled.
                0
            }
            WnfStateNameInformation::IsQuiescent => {
                if !exists {
                    return NtStatus::OBJECT_NAME_NOT_FOUND;
                }
                1
            }
        };
        buffer
            .write_at_offset(0, value)
            .map_or(NtStatus::ACCESS_VIOLATION, |()| NtStatus::SUCCESS)
    }

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
            let store = self.global.wnf_states.read();
            store.states.get(&state_name).cloned()
        };
        let Some(state) = state else {
            return NtStatus::OBJECT_NAME_NOT_FOUND;
        };
        if !type_id_matches(state.type_id, type_id) {
            return NtStatus::INVALID_PARAMETER;
        }

        let required_size = state.data.len().trunc();
        let status = if available_size < required_size {
            NtStatus::BUFFER_TOO_SMALL
        } else {
            if !state.data.is_empty() && buffer.write_slice_at_offset(0, &state.data).is_none() {
                return NtStatus::ACCESS_VIOLATION;
            }
            NtStatus::SUCCESS
        };
        if change_stamp
            .write_at_offset(0, state.change_stamp)
            .is_none()
            || buffer_size.write_at_offset(0, required_size).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        status
    }
}

fn read_type_id<Platform: ShimPlatform>(
    type_id: Option<ConstPtr<Platform, Guid>>,
) -> Result<Option<Guid>, NtStatus> {
    type_id
        .map(|type_id| type_id.read_at_offset(0).ok_or(NtStatus::ACCESS_VIOLATION))
        .transpose()
}

fn type_id_matches(expected: Option<Guid>, supplied: Option<Guid>) -> bool {
    expected.is_none()
        || matches!((expected, supplied), (Some(expected), Some(supplied)) if expected.data == supplied.data)
}

fn encode_state_name(
    lifetime: WnfStateNameLifetime,
    data_scope: WnfDataScope,
    persist_data: bool,
    unique_id: u32,
) -> u64 {
    let clear = 1
        | ((lifetime as u64) << 4)
        | ((data_scope as u64) << 6)
        | (u64::from(persist_data) << 10)
        | (u64::from(unique_id) << 11);
    clear ^ STATE_NAME_XOR_KEY
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestFS, TestPlatform, const_ptr, mut_byte_ptr, mut_ptr, test_task};

    const SECURITY_DESCRIPTOR_REVISION: u8 = 1;

    fn create_state(
        task: &Task<TestPlatform, TestFS>,
        type_id: Option<Guid>,
        maximum_state_size: u32,
    ) -> u64 {
        let mut state_name = 0;
        assert_eq!(
            task.sys_nt_create_wnf_state_name(WnfCreateStateNameParameters {
                state_name: mut_ptr(&mut state_name),
                name_lifetime: WnfStateNameLifetime::Temporary as u32,
                data_scope: WnfDataScope::Machine as u32,
                persist_data: 0,
                type_id: type_id.as_ref().map(const_ptr),
                maximum_state_size,
                security_descriptor: const_ptr(&SECURITY_DESCRIPTOR_REVISION),
            }),
            NtStatus::SUCCESS
        );
        state_name
    }

    fn update_state(
        task: &Task<TestPlatform, TestFS>,
        state_name: u64,
        data: &[u8],
        type_id: Option<&Guid>,
        matching_change_stamp: u32,
        check_stamp: i32,
    ) -> NtStatus {
        task.sys_nt_update_wnf_state_data(WnfUpdateStateDataParameters {
            state_name: const_ptr(&state_name),
            buffer: data.first().map(const_ptr),
            buffer_size: u32::try_from(data.len()).expect("test payload length fits in u32"),
            type_id: type_id.map(const_ptr),
            explicit_scope: None,
            matching_change_stamp,
            check_stamp,
        })
    }

    #[test]
    fn delete_data_resets_state_and_delete_name_removes_it() {
        let task = test_task();
        let state_name = create_state(&task, None, 4);
        assert_eq!(
            update_state(&task, state_name, &[1, 2], None, 0, 0),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_delete_wnf_state_data(const_ptr(&state_name), None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_delete_wnf_state_data(const_ptr(&state_name), None),
            NtStatus::SUCCESS
        );

        let mut change_stamp = 99;
        let mut buffer = [0xaau8; 2];
        let mut buffer_size = 2;
        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(change_stamp, 0);
        assert_eq!(buffer_size, 0);
        assert_eq!(buffer, [0xaa; 2]);

        assert_eq!(
            task.sys_nt_delete_wnf_state_name(const_ptr(&state_name)),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_delete_wnf_state_name(const_ptr(&state_name)),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            task.sys_nt_query_wnf_state_data(
                const_ptr(&state_name),
                None,
                None,
                mut_ptr(&mut change_stamp),
                mut_byte_ptr(&mut buffer),
                mut_ptr(&mut buffer_size),
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
    }

    #[test]
    fn state_name_information_reports_native_boolean_contract() {
        let task = test_task();
        let state_name = create_state(&task, None, 4);
        for (class, expected) in [
            (WnfStateNameInformation::Exists, 1),
            (WnfStateNameInformation::SubscribersPresent, 0),
            (WnfStateNameInformation::IsQuiescent, 1),
        ] {
            let mut value = u32::MAX;
            assert_eq!(
                task.sys_nt_query_wnf_state_name_information(
                    const_ptr(&state_name),
                    class as u32,
                    None,
                    mut_ptr(&mut value),
                    STATE_NAME_INFORMATION_SIZE,
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(value, expected);
        }

        assert_eq!(
            task.sys_nt_delete_wnf_state_name(const_ptr(&state_name)),
            NtStatus::SUCCESS
        );
        let mut value = u32::MAX;
        assert_eq!(
            task.sys_nt_query_wnf_state_name_information(
                const_ptr(&state_name),
                WnfStateNameInformation::Exists as u32,
                None,
                mut_ptr(&mut value),
                STATE_NAME_INFORMATION_SIZE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(value, 0);
        assert_eq!(
            task.sys_nt_query_wnf_state_name_information(
                const_ptr(&state_name),
                WnfStateNameInformation::SubscribersPresent as u32,
                None,
                mut_ptr(&mut value),
                STATE_NAME_INFORMATION_SIZE,
            ),
            NtStatus::OBJECT_NAME_NOT_FOUND
        );
        assert_eq!(
            task.sys_nt_query_wnf_state_name_information(
                const_ptr(&state_name),
                3,
                None,
                mut_ptr(&mut value),
                STATE_NAME_INFORMATION_SIZE,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
    }
}
