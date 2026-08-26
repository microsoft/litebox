// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT mutant object syscalls.

use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawMutPointer as _;
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ObjectAttributes, ObjectAttributesFlags};
use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct MutantAccess: u32 {
        const QUERY_STATE = 0x0001;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY_STATE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits()
            | AccessMask::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | AccessMask::SYNCHRONIZE.bits()
            | Self::QUERY_STATE.bits();

        const _ = !0;
    }
}

impl MutantAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        Self::from_bits_retain(AccessMask::expand_generic_access(
            desired_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        ))
    }
}

pub(crate) struct MutantSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for MutantSubsystem<Platform> {
    type Entry = MutantHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for MutantHandleObject<Platform> {}

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem for MutantSubsystem<Platform> {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        MutantAccess::from_desired_access(desired_access).bits()
    }
}

pub(crate) struct MutantHandleObject<Platform: crate::ShimPlatform> {
    pub(crate) mutant: Arc<MutantObject<Platform>>,
}

struct MutantState {
    owner: Option<usize>,
    current_count: i32,
}

pub(crate) struct MutantObject<Platform: crate::ShimPlatform> {
    state: Mutex<Platform, MutantState>,
    pollee: Pollee<Platform>,
}

impl<Platform: crate::ShimPlatform> MutantObject<Platform> {
    fn new(initial_owner: bool, thread_id: usize) -> Self {
        Self {
            state: Mutex::new(if initial_owner {
                MutantState {
                    owner: Some(thread_id),
                    current_count: 0,
                }
            } else {
                MutantState {
                    owner: None,
                    current_count: 1,
                }
            }),
            pollee: Pollee::new(),
        }
    }

    pub(crate) fn try_acquire(&self, thread_id: usize) -> bool {
        let mut state = self.state.lock();
        match state.owner {
            None => {
                state.owner = Some(thread_id);
                state.current_count = 0;
                true
            }
            Some(owner) if owner == thread_id => {
                let Some(current_count) = state.current_count.checked_sub(1) else {
                    return false;
                };
                state.current_count = current_count;
                true
            }
            Some(_) => false,
        }
    }

    fn release(&self, thread_id: usize) -> Result<i32, NtStatus> {
        let mut state = self.state.lock();
        if state.owner != Some(thread_id) {
            return Err(NtStatus::MUTANT_NOT_OWNED);
        }
        let previous_count = state.current_count;
        state.current_count += 1;
        if state.current_count == 1 {
            state.owner = None;
            drop(state);
            self.pollee.notify_observers(Events::IN);
        }
        Ok(previous_count)
    }

    fn query(&self, thread_id: usize) -> MutantBasicInformation {
        let state = self.state.lock();
        MutantBasicInformation {
            current_count: state.current_count,
            owned_by_caller: u8::from(state.owner == Some(thread_id)),
            abandoned_state: 0,
            padding: [0; 2],
        }
    }
}

impl<Platform: crate::ShimPlatform> IOPollable for MutantObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if self.state.lock().owner.is_none() {
            Events::IN
        } else {
            Events::empty()
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct MutantBasicInformation {
    current_count: i32,
    owned_by_caller: u8,
    abandoned_state: u8,
    padding: [u8; 2],
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn insert_mutant_handle(
        &self,
        mutant: Arc<MutantObject<Platform>>,
        granted_access: MutantAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<MutantSubsystem<Platform>>(
            MutantHandleObject { mutant },
            granted_access.bits(),
            drop,
        )
    }

    pub(crate) fn close_mutant(mutant: MutantHandleObject<Platform>) {
        drop(mutant);
    }

    pub(crate) fn sys_nt_create_mutant(
        &self,
        mutant_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        initial_owner: u8,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(mutant_handle) {
            return status;
        }
        let (object_attributes, mutant_name) =
            match self.read_dispatcher_object_attributes(object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = MutantAccess::from_desired_access(desired_access);

        if let Some(mutant_name) = mutant_name {
            litebox_util_log::debug!(mutant_name:% = mutant_name; "Creating named mutant");
            let mutant = Arc::new(MutantObject::new(initial_owner != 0, self.thread_id));
            return self.process.object_manager.create_mutant(
                &mutant_name,
                &mutant,
                |mutant| {
                    let Some(object_attributes) = object_attributes else {
                        return NtStatus::INVALID_PARAMETER;
                    };
                    if !ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                        .contains(ObjectAttributesFlags::OPENIF)
                    {
                        return NtStatus::OBJECT_NAME_COLLISION;
                    }
                    self.write_new_mutant_handle(mutant_handle, mutant, granted_access)
                        .map_or_else(|status| status, |()| NtStatus::OBJECT_NAME_EXISTS)
                },
                || {
                    self.write_new_mutant_handle(mutant_handle, Arc::clone(&mutant), granted_access)
                        .map_or_else(|status| status, |()| NtStatus::SUCCESS)
                },
            );
        }

        let mutant = Arc::new(MutantObject::new(initial_owner != 0, self.thread_id));
        self.write_new_mutant_handle(mutant_handle, mutant, granted_access)
            .map_or_else(|status| status, |()| NtStatus::SUCCESS)
    }

    pub(crate) fn sys_nt_open_mutant(
        &self,
        mutant_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(mutant_handle) {
            return status;
        }
        let mutant_name = match self.read_dispatcher_object_attributes(object_attributes, true) {
            Ok((_, Some(mutant_name))) => mutant_name,
            Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
            Err(status) => return status,
        };
        let mutant = match self.process.object_manager.resolve_mutant(&mutant_name) {
            Ok(mutant) => mutant,
            Err(status) => return status,
        };
        self.write_new_mutant_handle(
            mutant_handle,
            mutant,
            MutantAccess::from_desired_access(desired_access),
        )
        .map_or_else(|status| status, |()| NtStatus::SUCCESS)
    }

    pub(crate) fn sys_nt_release_mutant(
        &self,
        mutant_handle: Handle,
        previous_count: Option<MutPtr<Platform, i32>>,
    ) -> NtStatus {
        if let Some(previous_count) = previous_count
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(previous_count)
        {
            return status;
        }
        let entry = match self.typed_handle_entry::<MutantSubsystem<Platform>>(mutant_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let previous = match entry.with_entry(|entry| entry.mutant.release(self.thread_id)) {
            Ok(previous) => previous,
            Err(status) => return status,
        };
        if let Some(previous_count) = previous_count
            && previous_count.write_at_offset(0, previous).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_mutant(
        &self,
        mutant_handle: Handle,
        mutant_information_class: u32,
        mutant_information: MutPtr<Platform, MutantBasicInformation>,
        mutant_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        if mutant_information_class != 0 {
            return NtStatus::INVALID_INFO_CLASS;
        }
        let required_length = u32::try_from(size_of::<MutantBasicInformation>()).unwrap();
        if mutant_information_length != required_length {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(mutant_information)
        {
            return status;
        }
        if let Some(return_length) = return_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(return_length)
        {
            return status;
        }
        let entry = match self.typed_handle_entry_with_access::<MutantSubsystem<Platform>>(
            mutant_handle,
            MutantAccess::QUERY_STATE.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let information = entry.with_entry(|entry| entry.mutant.query(self.thread_id));
        if mutant_information.write_at_offset(0, information).is_none()
            || return_length.is_some_and(|return_length| {
                return_length.write_at_offset(0, required_length).is_none()
            })
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_new_mutant_handle(
        &self,
        output: MutPtr<Platform, Handle>,
        mutant: Arc<MutantObject<Platform>>,
        granted_access: MutantAccess,
    ) -> Result<(), NtStatus> {
        let handle = self
            .insert_mutant_handle(mutant, granted_access)
            .map_err(|_| NtStatus::QUOTA_EXCEEDED)?;
        if output.write_at_offset(0, handle).is_none() {
            self.close_typed_handle::<MutantSubsystem<Platform>>(handle, drop);
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of_val;

    use super::*;
    use crate::tests::{const_ptr, mut_ptr, test_task};

    const MUTANT_ALL_ACCESS: u32 = 0x001f_0001;

    #[test]
    fn mutant_waits_are_recursive_and_release_restores_signal() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_mutant(mut_ptr(&mut handle), MUTANT_ALL_ACCESS, None, 0),
            NtStatus::SUCCESS
        );

        let timeout = 0i64;
        assert_eq!(
            task.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout))),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout))),
            NtStatus::SUCCESS
        );

        let mut previous_count = i32::MAX;
        assert_eq!(
            task.sys_nt_release_mutant(handle, Some(mut_ptr(&mut previous_count))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous_count, -1);
        assert_eq!(task.sys_nt_release_mutant(handle, None), NtStatus::SUCCESS);
    }

    #[test]
    fn mutant_query_reports_current_thread_ownership() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_mutant(mut_ptr(&mut handle), MUTANT_ALL_ACCESS, None, 1),
            NtStatus::SUCCESS
        );
        let mut information = MutantBasicInformation {
            current_count: i32::MAX,
            owned_by_caller: 0,
            abandoned_state: u8::MAX,
            padding: [u8::MAX; 2],
        };
        let mut return_length = 0;
        assert_eq!(
            task.sys_nt_query_mutant(
                handle,
                0,
                mut_ptr(&mut information),
                size_of_val(&information).try_into().unwrap(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(information.current_count, 0);
        assert_eq!(information.owned_by_caller, 1);
        assert_eq!(information.abandoned_state, 0);
        assert_eq!(return_length as usize, size_of_val(&information));
    }
}
