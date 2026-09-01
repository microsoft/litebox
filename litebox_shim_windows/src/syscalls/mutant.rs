// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT mutant object syscalls.

use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::mem::size_of;
use litebox::utils::TruncateExt;

use int_enum::IntEnum;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::RawMutPointer as _;
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ClientId, ObjectAttributes, ObjectAttributesFlags};
use crate::syscalls::thread::ThreadObject;
use crate::syscalls::{Handle, WaitAcquireResult};
use crate::{ConstPtr, MutPtr, Task, probe_guest_output_preserving_value};

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

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum MutantInformationClass {
    Basic = 0,
    Owner = 1,
}

struct MutantState {
    owner: Option<usize>,
    current_count: i32,
    abandoned: bool,
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
                    abandoned: false,
                }
            } else {
                MutantState {
                    owner: None,
                    current_count: 1,
                    abandoned: false,
                }
            }),
            pollee: Pollee::new(),
        }
    }

    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        thread_id: usize,
        thread: &ThreadObject<Platform>,
    ) -> Option<WaitAcquireResult> {
        let mut state = self.state.lock();
        match state.owner {
            None => {
                state.owner = Some(thread_id);
                state.current_count = 0;
                let abandoned = core::mem::take(&mut state.abandoned);
                drop(state);
                thread.register_owned_mutant(self);
                if abandoned {
                    Some(WaitAcquireResult::Abandoned)
                } else {
                    Some(WaitAcquireResult::Acquired)
                }
            }
            Some(owner) if owner == thread_id => {
                state.current_count = state.current_count.checked_sub(1)?;
                Some(WaitAcquireResult::Acquired)
            }
            Some(_) => None,
        }
    }

    fn release(
        self: &Arc<Self>,
        thread_id: usize,
        thread: &ThreadObject<Platform>,
    ) -> Result<i32, NtStatus> {
        let mut state = self.state.lock();
        if state.owner != Some(thread_id) {
            return Err(NtStatus::MUTANT_NOT_OWNED);
        }
        let previous_count = state.current_count;
        state.current_count += 1;
        if state.current_count == 1 {
            state.owner = None;
            drop(state);
            thread.unregister_owned_mutant(self);
            self.pollee.notify_observers(Events::IN);
        }
        Ok(previous_count)
    }

    pub(crate) fn abandon(&self, thread_id: usize) {
        let mut state = self.state.lock();
        if state.owner != Some(thread_id) {
            return;
        }
        state.owner = None;
        state.current_count = 1;
        state.abandoned = true;
        drop(state);
        self.pollee.notify_observers(Events::IN);
    }

    fn query_basic(&self, thread_id: usize) -> MutantBasicInformation {
        let state = self.state.lock();
        MutantBasicInformation {
            current_count: state.current_count,
            owned_by_caller: u8::from(state.owner == Some(thread_id)),
            abandoned_state: u8::from(state.abandoned),
            padding: [0; 2],
        }
    }

    fn query_owner(&self, process_id: usize) -> MutantOwnerInformation {
        let state = self.state.lock();
        MutantOwnerInformation {
            client_id: match state.owner {
                Some(thread_id) => ClientId {
                    unique_process: process_id,
                    unique_thread: thread_id,
                },
                None => ClientId {
                    unique_process: 0,
                    unique_thread: 0,
                },
            },
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
struct MutantOwnerInformation {
    client_id: ClientId,
}

impl<Platform: crate::ShimPlatform> Task<Platform> {
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
            let mutant = Arc::new(MutantObject::new(
                initial_owner != 0,
                self.thread_object.thread_id(),
            ));
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
                    self.write_created_mutant_handle(
                        mutant_handle,
                        Arc::clone(&mutant),
                        granted_access,
                        initial_owner != 0,
                    )
                },
            );
        }

        let mutant = Arc::new(MutantObject::new(
            initial_owner != 0,
            self.thread_object.thread_id(),
        ));
        self.write_created_mutant_handle(mutant_handle, mutant, granted_access, initial_owner != 0)
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
        let previous = match entry.with_entry(|entry| {
            entry
                .mutant
                .release(self.thread_object.thread_id(), &self.thread_object)
        }) {
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
        mutant_information: MutPtr<Platform, u8>,
        mutant_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Ok(mutant_information_class) =
            MutantInformationClass::try_from(mutant_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        let required_length = match mutant_information_class {
            MutantInformationClass::Basic => size_of::<MutantBasicInformation>(),
            MutantInformationClass::Owner => size_of::<MutantOwnerInformation>(),
        };
        let required_length: u32 = required_length.trunc();
        if mutant_information_length != required_length {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, u8>(mutant_information)
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
        let written = entry.with_entry(|entry| match mutant_information_class {
            MutantInformationClass::Basic => mutant_information
                .write_slice_at_offset(
                    0,
                    entry
                        .mutant
                        .query_basic(self.thread_object.thread_id())
                        .as_bytes(),
                )
                .is_some(),
            MutantInformationClass::Owner => mutant_information
                .write_slice_at_offset(0, entry.mutant.query_owner(self.process.id).as_bytes())
                .is_some(),
        });
        if !written {
            return NtStatus::ACCESS_VIOLATION;
        }
        if return_length.is_some_and(|return_length| {
            return_length.write_at_offset(0, required_length).is_none()
        }) {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_created_mutant_handle(
        &self,
        output: MutPtr<Platform, Handle>,
        mutant: Arc<MutantObject<Platform>>,
        granted_access: MutantAccess,
        initial_owner: bool,
    ) -> NtStatus {
        match self.write_new_mutant_handle(output, Arc::clone(&mutant), granted_access) {
            Ok(()) => {
                if initial_owner {
                    self.thread_object.register_owned_mutant(&mutant);
                }
                NtStatus::SUCCESS
            }
            Err(status) => status,
        }
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
    extern crate std;

    use super::*;
    use crate::tests::{const_ptr, mut_ptr, run_with_test_platform_pointers, test_task};
    use core::time::Duration;

    const MUTANT_ALL_ACCESS: u32 = 0x001f_0001;

    #[test]
    fn owner_exit_wakes_blocked_waiter_as_abandoned() {
        run_with_test_platform_pointers(|| {
            let owner = test_task();
            let waiter = owner.clone_for_test().expect("process is live");
            let mut handle = Handle::default();
            assert_eq!(
                owner.sys_nt_create_mutant(mut_ptr(&mut handle), MUTANT_ALL_ACCESS, None, 1),
                NtStatus::SUCCESS
            );

            let (started_tx, started_rx) = std::sync::mpsc::channel();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let timeout = -10_000_000i64;
                started_tx.send(()).unwrap();
                let status =
                    waiter.sys_nt_wait_for_single_object(handle, false, Some(const_ptr(&timeout)));
                result_tx.send(status).unwrap();
                assert_eq!(
                    waiter.sys_nt_release_mutant(handle, None),
                    NtStatus::SUCCESS
                );
                assert_eq!(waiter.sys_nt_close(handle), NtStatus::SUCCESS);
            });

            started_rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(20));
            owner.complete_current_thread();
            assert_eq!(
                result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                NtStatus::ABANDONED_WAIT_0
            );
            thread.join().unwrap();
        });
    }
}
