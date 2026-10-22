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

use crate::nt_types::{AccessMask, ClientId, ObjectAttributes};
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

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem<Platform>
    for MutantSubsystem<Platform>
{
    fn normalize_desired_access(desired_access: u32) -> u32 {
        MutantAccess::from_desired_access(desired_access).bits()
    }

    fn waitable_object(
        entry: &Self::Entry,
    ) -> Option<crate::syscalls::wait::WaitableObject<Platform>> {
        Some(crate::syscalls::wait::WaitableObject::Mutant(
            alloc::sync::Arc::clone(&entry.mutant),
        ))
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
    pub(crate) fn sys_nt_create_mutant(
        &self,
        mutant_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        initial_owner: bool,
    ) -> NtStatus {
        self.create_named_dispatcher_object(
            mutant_handle,
            desired_access,
            object_attributes,
            || {
                Ok(Arc::new(MutantObject::new(
                    initial_owner,
                    self.thread_object.thread_id(),
                )))
            },
            |mutant| {
                if initial_owner {
                    self.thread_object.register_owned_mutant(mutant);
                }
            },
        )
    }

    pub(crate) fn sys_nt_open_mutant(
        &self,
        mutant_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        self.open_named_dispatcher_object::<MutantObject<Platform>>(
            mutant_handle,
            desired_access,
            object_attributes,
        )
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
                owner.sys_nt_create_mutant(mut_ptr(&mut handle), MUTANT_ALL_ACCESS, None, true),
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

    #[test]
    fn named_create_registers_initial_owner_and_open_shares_the_mutant() {
        use crate::nt_types::ObjectAttributesFlags;
        use crate::tests::{object_attributes, unicode_string, utf16_units};

        run_with_test_platform_pointers(|| {
            let owner = test_task();
            let waiter = owner.clone_for_test().expect("process is live");
            let name_units = utf16_units("\\BaseNamedObjects\\LiteBoxNamedMutant");
            let name = unicode_string(&name_units);
            let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
            let openif_attrs = ObjectAttributes {
                attributes: (ObjectAttributesFlags::CASE_INSENSITIVE
                    | ObjectAttributesFlags::OPENIF)
                    .bits(),
                ..attrs
            };

            let mut created = Handle::default();
            assert_eq!(
                owner.sys_nt_create_mutant(
                    mut_ptr(&mut created),
                    MUTANT_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    true,
                ),
                NtStatus::SUCCESS
            );
            let mut collision = Handle::default();
            assert_eq!(
                waiter.sys_nt_create_mutant(
                    mut_ptr(&mut collision),
                    MUTANT_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                    true,
                ),
                NtStatus::OBJECT_NAME_COLLISION
            );
            assert_eq!(
                waiter.sys_nt_create_mutant(
                    mut_ptr(&mut collision),
                    MUTANT_ALL_ACCESS,
                    Some(const_ptr(&openif_attrs)),
                    true,
                ),
                NtStatus::OBJECT_NAME_EXISTS
            );
            assert_eq!(waiter.sys_nt_close(collision), NtStatus::SUCCESS);
            let mut opened = Handle::default();
            assert_eq!(
                waiter.sys_nt_open_mutant(
                    mut_ptr(&mut opened),
                    MUTANT_ALL_ACCESS,
                    Some(const_ptr(&attrs)),
                ),
                NtStatus::SUCCESS
            );

            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let timeout = -10_000_000i64;
                let status =
                    waiter.sys_nt_wait_for_single_object(opened, false, Some(const_ptr(&timeout)));
                result_tx.send(status).unwrap();
                assert_eq!(
                    waiter.sys_nt_release_mutant(opened, None),
                    NtStatus::SUCCESS
                );
            });

            std::thread::sleep(Duration::from_millis(20));
            owner.complete_current_thread();
            assert_eq!(
                result_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                NtStatus::ABANDONED_WAIT_0
            );
            thread.join().unwrap();
        });
    }

    fn named_attributes(
        name: &crate::nt_types::UnicodeString,
        open_if: bool,
    ) -> crate::nt_types::ObjectAttributes {
        use crate::nt_types::ObjectAttributesFlags;

        let mut flags = ObjectAttributesFlags::CASE_INSENSITIVE;
        if open_if {
            flags |= ObjectAttributesFlags::OPENIF;
        }
        crate::tests::object_attributes(name, flags.bits())
    }

    /// Statuses observed for create/open/release calls that reuse a name; compared against the
    /// host by the `host_fidelity` tests.
    #[derive(Debug, Eq, PartialEq)]
    struct OpenIfOwnershipStatuses {
        create: i32,
        openif_create: i32,
        release_reopened: i32,
    }

    fn shim_openif_ownership(name: &crate::nt_types::UnicodeString) -> OpenIfOwnershipStatuses {
        let task = test_task();
        let attributes = named_attributes(name, true);
        let mut created = Handle::default();
        let mut reopened = Handle::default();
        let create = task.sys_nt_create_mutant(
            mut_ptr(&mut created),
            MUTANT_ALL_ACCESS,
            Some(const_ptr(&attributes)),
            false,
        );
        let openif_create = task.sys_nt_create_mutant(
            mut_ptr(&mut reopened),
            MUTANT_ALL_ACCESS,
            Some(const_ptr(&attributes)),
            true,
        );
        let release_reopened = task.sys_nt_release_mutant(reopened, None);
        OpenIfOwnershipStatuses {
            create: create.as_raw(),
            openif_create: openif_create.as_raw(),
            release_reopened: release_reopened.as_raw(),
        }
    }

    #[test]
    fn openif_create_of_existing_mutant_does_not_take_initial_ownership() {
        let name_units = crate::tests::utf16_units("\\BaseNamedObjects\\LiteBoxOpenIfMutant");
        let name = crate::tests::unicode_string(&name_units);
        assert_eq!(
            shim_openif_ownership(&name),
            OpenIfOwnershipStatuses {
                create: NtStatus::SUCCESS.as_raw(),
                openif_create: NtStatus::OBJECT_NAME_EXISTS.as_raw(),
                release_reopened: NtStatus::MUTANT_NOT_OWNED.as_raw(),
            }
        );
    }

    #[derive(Debug, Eq, PartialEq)]
    struct TypeMismatchStatuses {
        open: i32,
        create: i32,
        openif_create: i32,
        output_untouched: bool,
    }

    fn shim_mutant_on_event_name(name: &crate::nt_types::UnicodeString) -> TypeMismatchStatuses {
        let task = test_task();
        let attributes = named_attributes(name, false);
        let openif_attributes = named_attributes(name, true);
        let mut event = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut event),
                MUTANT_ALL_ACCESS,
                Some(const_ptr(&attributes)),
                0,
                false,
            ),
            NtStatus::SUCCESS
        );

        let sentinel = Handle::from_raw(0x1234);
        let mut output = sentinel;
        let open = task.sys_nt_open_mutant(
            mut_ptr(&mut output),
            MUTANT_ALL_ACCESS,
            Some(const_ptr(&attributes)),
        );
        let create = task.sys_nt_create_mutant(
            mut_ptr(&mut output),
            MUTANT_ALL_ACCESS,
            Some(const_ptr(&attributes)),
            false,
        );
        let openif_create = task.sys_nt_create_mutant(
            mut_ptr(&mut output),
            MUTANT_ALL_ACCESS,
            Some(const_ptr(&openif_attributes)),
            false,
        );
        TypeMismatchStatuses {
            open: open.as_raw(),
            create: create.as_raw(),
            openif_create: openif_create.as_raw(),
            output_untouched: output == sentinel,
        }
    }

    #[test]
    fn mutant_create_and_open_reject_a_name_owned_by_another_type() {
        let name_units = crate::tests::utf16_units("\\BaseNamedObjects\\LiteBoxEventNotMutant");
        let name = crate::tests::unicode_string(&name_units);
        assert_eq!(
            shim_mutant_on_event_name(&name),
            TypeMismatchStatuses {
                open: NtStatus::OBJECT_TYPE_MISMATCH.as_raw(),
                create: NtStatus::OBJECT_TYPE_MISMATCH.as_raw(),
                openif_create: NtStatus::OBJECT_TYPE_MISMATCH.as_raw(),
                output_untouched: true,
            }
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    mod host_fidelity {
        use core::ffi::c_void;

        use super::*;
        use crate::nt_types::{ObjectAttributes, UnicodeString};

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtCreateMutant(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                initial_owner: u8,
            ) -> i32;
            fn NtOpenMutant(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
            ) -> i32;
            fn NtReleaseMutant(handle: *mut c_void, previous_count: *mut i32) -> i32;
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        fn close_host_handle(handle: *mut c_void) {
            if !handle.is_null() {
                // SAFETY: The handle was returned by a successful host ntdll call in this test.
                assert_eq!(unsafe { NtClose(handle) }, NtStatus::SUCCESS.as_raw());
            }
        }

        fn unique_name(prefix: &str, unique: *const u8) -> alloc::vec::Vec<u16> {
            crate::tests::utf16_units(&alloc::format!(r"\BaseNamedObjects\{prefix}{unique:p}"))
        }

        fn host_openif_ownership(name: &UnicodeString) -> OpenIfOwnershipStatuses {
            let attributes = named_attributes(name, true);
            let mut created = core::ptr::null_mut();
            let mut reopened = core::ptr::null_mut();
            // SAFETY: Pointers reference live stack locals and `attributes` names a live
            // UnicodeString for the duration of the calls; `reopened` is only released after a
            // successful open.
            let statuses = unsafe {
                let create = NtCreateMutant(
                    &raw mut created,
                    MUTANT_ALL_ACCESS,
                    &raw const attributes,
                    0,
                );
                let openif_create = NtCreateMutant(
                    &raw mut reopened,
                    MUTANT_ALL_ACCESS,
                    &raw const attributes,
                    1,
                );
                OpenIfOwnershipStatuses {
                    create,
                    openif_create,
                    release_reopened: NtReleaseMutant(reopened, core::ptr::null_mut()),
                }
            };
            close_host_handle(reopened);
            close_host_handle(created);
            statuses
        }

        fn host_mutant_on_event_name(name: &UnicodeString) -> TypeMismatchStatuses {
            let attributes = named_attributes(name, false);
            let openif_attributes = named_attributes(name, true);
            let mut event = core::ptr::null_mut();
            // SAFETY: Pointers reference live stack locals and `attributes` names a live
            // UnicodeString for the duration of the call.
            let event_status = unsafe {
                NtCreateEvent(
                    &raw mut event,
                    MUTANT_ALL_ACCESS,
                    &raw const attributes,
                    0,
                    0,
                )
            };
            assert_eq!(event_status, NtStatus::SUCCESS.as_raw());

            let sentinel = 0x1234 as *mut c_void;
            let mut output = sentinel;
            // SAFETY: As above; every call targets the same live `output` local.
            let statuses = unsafe {
                TypeMismatchStatuses {
                    open: NtOpenMutant(&raw mut output, MUTANT_ALL_ACCESS, &raw const attributes),
                    create: NtCreateMutant(
                        &raw mut output,
                        MUTANT_ALL_ACCESS,
                        &raw const attributes,
                        0,
                    ),
                    openif_create: NtCreateMutant(
                        &raw mut output,
                        MUTANT_ALL_ACCESS,
                        &raw const openif_attributes,
                        0,
                    ),
                    output_untouched: false,
                }
            };
            let statuses = TypeMismatchStatuses {
                output_untouched: output == sentinel,
                ..statuses
            };
            close_host_handle(event);
            statuses
        }

        #[test]
        fn openif_mutant_ownership_matches_host() {
            let unique = 0u8;
            let host_units = unique_name("LiteBoxOpenIfMutantHost", &raw const unique);
            let shim_units = unique_name("LiteBoxOpenIfMutantShim", &raw const unique);
            assert_eq!(
                shim_openif_ownership(&crate::tests::unicode_string(&shim_units)),
                host_openif_ownership(&crate::tests::unicode_string(&host_units)),
            );
        }

        #[test]
        fn mutant_type_mismatch_matches_host() {
            let unique = 0u8;
            let host_units = unique_name("LiteBoxEventNotMutantHost", &raw const unique);
            let shim_units = unique_name("LiteBoxEventNotMutantShim", &raw const unique);
            assert_eq!(
                shim_mutant_on_event_name(&crate::tests::unicode_string(&shim_units)),
                host_mutant_on_event_name(&crate::tests::unicode_string(&host_units)),
            );
        }
    }
}
