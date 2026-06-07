// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT event object syscalls.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::mem::size_of;

use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{AccessMask, ObjectAttributes, UnicodeString, read_object_attributes};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, probe_guest_output_preserving_value,
    raw_handle_entry, remove_raw_handle,
};

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const OBJ_OPENIF: u32 = 0x0000_0080;
const OBJ_OPENLINK: u32 = 0x0000_0100;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EventType {
    Notification = 0,
    Synchronization = 1,
}

impl EventType {
    fn from_raw(raw: u32) -> Result<Self, NtStatus> {
        match raw {
            0 => Ok(Self::Notification),
            1 => Ok(Self::Synchronization),
            _ => Err(NtStatus::INVALID_PARAMETER),
        }
    }

    const fn as_raw(self) -> u32 {
        self as u32
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct EventBasicInformation {
    event_type: u32,
    event_state: i32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventInformationClass {
    Basic = 0,
}

impl EventInformationClass {
    fn from_raw(raw: u32) -> Result<Self, NtStatus> {
        match raw {
            0 => Ok(Self::Basic),
            _ => Err(NtStatus::INVALID_INFO_CLASS),
        }
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct EventAccess: u32 {
        const QUERY_STATE = 0x0001;
        const MODIFY_STATE = 0x0002;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY_STATE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::MODIFY_STATE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits() | AccessMask::SYNCHRONIZE.bits();
        const ALL_ACCESS = AccessMask::STANDARD_RIGHTS_ALL.bits()
            | Self::QUERY_STATE.bits()
            | Self::MODIFY_STATE.bits();

        const _ = !0;
    }
}

impl EventAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let mut access = Self::from_bits_retain(desired_access);
        if desired_access & AccessMask::GENERIC_READ.bits() != 0 {
            access.insert(Self::READ);
        }
        if desired_access & AccessMask::GENERIC_WRITE.bits() != 0 {
            access.insert(Self::WRITE);
        }
        if desired_access & AccessMask::GENERIC_EXECUTE.bits() != 0 {
            access.insert(Self::EXECUTE);
        }
        if desired_access & AccessMask::GENERIC_ALL.bits() != 0 {
            access.insert(Self::ALL_ACCESS);
        }
        access.remove(Self::from_bits_retain(
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits()
                | AccessMask::GENERIC_ALL.bits(),
        ));
        access
    }

    fn require(self, required: Self) -> Result<(), NtStatus> {
        if self.contains(required) {
            Ok(())
        } else {
            Err(NtStatus::ACCESS_DENIED)
        }
    }
}

pub(crate) struct EventSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for EventSubsystem<Platform> {
    type Entry = EventHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for EventHandleObject<Platform> {}

pub(crate) struct EventHandleObject<Platform: crate::ShimPlatform> {
    event: Arc<EventObject<Platform>>,
    granted_access: EventAccess,
}

pub(crate) struct EventObject<Platform: crate::ShimPlatform> {
    event_type: EventType,
    signaled: Mutex<Platform, bool>,
    pollee: Pollee<Platform>,
}

impl<Platform: crate::ShimPlatform> EventObject<Platform> {
    fn new(event_type: EventType, initial_state: bool) -> Self {
        Self {
            event_type,
            signaled: Mutex::new(initial_state),
            pollee: Pollee::new(),
        }
    }

    fn set(&self) -> i32 {
        let previous = self.replace_state(true);
        if previous == 0 {
            self.pollee.notify_observers(Events::IN);
        }
        previous
    }

    fn reset(&self) -> i32 {
        self.replace_state(false)
    }

    fn clear(&self) {
        *self.signaled.lock() = false;
    }

    fn pulse(&self) -> i32 {
        self.replace_state(false)
    }

    fn query(&self) -> EventBasicInformation {
        EventBasicInformation {
            event_type: self.event_type.as_raw(),
            event_state: i32::from(*self.signaled.lock()),
        }
    }

    fn replace_state(&self, next: bool) -> i32 {
        let mut signaled = self.signaled.lock();
        let previous = i32::from(*signaled);
        *signaled = next;
        previous
    }
}

impl<Platform: crate::ShimPlatform> IOPollable for EventObject<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        if *self.signaled.lock() {
            Events::IN
        } else {
            Events::empty()
        }
    }
}

struct EventName {
    key: String,
}

const EVENT_BASIC_INFORMATION_SIZE_U32: u32 = 8;
const _: () =
    assert!(size_of::<EventBasicInformation>() == EVENT_BASIC_INFORMATION_SIZE_U32 as usize);

fn read_event_name<Platform: RawPointerProvider>(
    object_name: usize,
    object_attributes: &ObjectAttributes,
) -> Result<Option<EventName>, NtStatus> {
    if object_name == 0 {
        if !object_attributes.root_directory.is_null() {
            return Err(NtStatus::OBJECT_NAME_INVALID);
        }
        return Ok(None);
    }
    if !object_attributes.root_directory.is_null() {
        return Err(NtStatus::OBJECT_PATH_NOT_FOUND);
    }

    let unicode_string = ConstPtr::<Platform, UnicodeString>::from_usize(object_name)
        .read_at_offset(0)
        .ok_or(NtStatus::ACCESS_VIOLATION)?;
    if unicode_string.length == 0 || !unicode_string.length.is_multiple_of(2) {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if unicode_string.buffer == 0 {
        return Err(NtStatus::ACCESS_VIOLATION);
    }
    let mut key = unicode_string.read_string::<Platform>()?;
    if key.is_empty() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    if object_attributes.attributes & OBJ_CASE_INSENSITIVE != 0 {
        key = key.to_ascii_lowercase();
    }
    Ok(Some(EventName { key }))
}

fn read_event_object_attributes<Platform: RawPointerProvider>(
    object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    require_name: bool,
) -> Result<(Option<ObjectAttributes>, Option<EventName>), NtStatus> {
    let Some(object_attributes_ptr) = object_attributes else {
        if require_name {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        return Ok((None, None));
    };
    let object_attributes = read_object_attributes::<Platform>(object_attributes_ptr)?;
    if object_attributes.attributes & OBJ_OPENLINK != 0 {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    let event_name =
        read_event_name::<Platform>(object_attributes.object_name, &object_attributes)?;
    if require_name && event_name.is_none() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok((Some(object_attributes), event_name))
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn event_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, EventSubsystem<Platform>>, NtStatus> {
        raw_handle_entry::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
        )
        .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn insert_event_handle(
        &self,
        event: Arc<EventObject<Platform>>,
        granted_access: EventAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<EventSubsystem<Platform>>(EventHandleObject {
                event,
                granted_access,
            });
        insert_raw_handle::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_event_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, EventSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_event(event: EventHandleObject<Platform>) {
        drop(event);
    }

    pub(crate) fn sys_nt_create_event(
        &self,
        event_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
        event_type: u32,
        initial_state: u8,
    ) -> NtStatus {
        let Ok(event_type) = EventType::from_raw(event_type) else {
            return NtStatus::INVALID_PARAMETER;
        };
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(event_handle) {
            return status;
        }

        let (object_attributes, event_name) =
            match read_event_object_attributes::<Platform>(object_attributes, false) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let granted_access = EventAccess::from_desired_access(desired_access);

        if let Some(event_name) = event_name {
            let existing = {
                let mut namespace = self.process.event_namespace.write();
                if let Some(event) = namespace.get(&event_name.key).and_then(Weak::upgrade) {
                    Some(event)
                } else {
                    namespace.remove(&event_name.key);
                    None
                }
            };
            if let Some(event) = existing {
                let Some(object_attributes) = object_attributes else {
                    return NtStatus::INVALID_PARAMETER;
                };
                if object_attributes.attributes & OBJ_OPENIF == 0 {
                    return NtStatus::OBJECT_NAME_COLLISION;
                }
                let Ok(handle) = self.insert_event_handle(event, granted_access) else {
                    return NtStatus::QUOTA_EXCEEDED;
                };
                if event_handle.write_at_offset(0, handle).is_none() {
                    self.close_event_handle(handle);
                    return NtStatus::ACCESS_VIOLATION;
                }
                return NtStatus::OBJECT_NAME_EXISTS;
            }

            let event = Arc::new(EventObject::new(event_type, initial_state != 0));
            let Ok(handle) = self.insert_event_handle(event.clone(), granted_access) else {
                return NtStatus::QUOTA_EXCEEDED;
            };
            {
                let mut namespace = self.process.event_namespace.write();
                namespace.insert(event_name.key, Arc::downgrade(&event));
            }
            if event_handle.write_at_offset(0, handle).is_none() {
                self.close_event_handle(handle);
                return NtStatus::ACCESS_VIOLATION;
            }
            return NtStatus::SUCCESS;
        }

        let event = Arc::new(EventObject::new(event_type, initial_state != 0));
        let Ok(handle) = self.insert_event_handle(event, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if event_handle.write_at_offset(0, handle).is_none() {
            self.close_event_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_open_event(
        &self,
        event_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(event_handle) {
            return status;
        }
        let event_name = match read_event_object_attributes::<Platform>(object_attributes, true) {
            Ok((_, Some(event_name))) => event_name,
            Ok((_, None)) => return NtStatus::OBJECT_NAME_INVALID,
            Err(status) => return status,
        };
        let event = {
            let mut namespace = self.process.event_namespace.write();
            if let Some(event) = namespace.get(&event_name.key).and_then(Weak::upgrade) {
                event
            } else {
                namespace.remove(&event_name.key);
                return NtStatus::OBJECT_NAME_NOT_FOUND;
            }
        };

        let Ok(handle) =
            self.insert_event_handle(event, EventAccess::from_desired_access(desired_access))
        else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if event_handle.write_at_offset(0, handle).is_none() {
            self.close_event_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_set_event(
        &self,
        event_handle: Handle,
        previous_state: Option<MutPtr<Platform, i32>>,
    ) -> NtStatus {
        if let Some(previous_state) = previous_state
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(previous_state)
        {
            return status;
        }

        self.modify_event(event_handle, previous_state, EventObject::set)
    }

    pub(crate) fn sys_nt_reset_event(
        &self,
        event_handle: Handle,
        previous_state: Option<MutPtr<Platform, i32>>,
    ) -> NtStatus {
        if let Some(previous_state) = previous_state
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(previous_state)
        {
            return status;
        }

        self.modify_event(event_handle, previous_state, EventObject::reset)
    }

    pub(crate) fn sys_nt_clear_event(&self, event_handle: Handle) -> NtStatus {
        let Ok(entry) = self.event_entry(event_handle) else {
            return NtStatus::INVALID_HANDLE;
        };
        entry
            .with_entry(|entry| {
                entry
                    .granted_access
                    .require(EventAccess::MODIFY_STATE)
                    .map(|()| entry.event.clear())
            })
            .map_or_else(|status| status, |()| NtStatus::SUCCESS)
    }

    pub(crate) fn sys_nt_pulse_event(
        &self,
        event_handle: Handle,
        previous_state: Option<MutPtr<Platform, i32>>,
    ) -> NtStatus {
        if let Some(previous_state) = previous_state
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(previous_state)
        {
            return status;
        }

        self.modify_event(event_handle, previous_state, EventObject::pulse)
    }

    pub(crate) fn sys_nt_query_event(
        &self,
        event_handle: Handle,
        event_information_class: u32,
        event_information: MutPtr<Platform, EventBasicInformation>,
        event_information_length: u32,
        return_length: Option<MutPtr<Platform, u32>>,
    ) -> NtStatus {
        let Ok(EventInformationClass::Basic) =
            EventInformationClass::from_raw(event_information_class)
        else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if event_information_length as usize != size_of::<EventBasicInformation>() {
            return NtStatus::INFO_LENGTH_MISMATCH;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(event_information) {
            return status;
        }
        if let Some(return_length) = return_length
            && let Err(status) = probe_guest_output_preserving_value::<Platform, _>(return_length)
        {
            return status;
        }

        let Ok(entry) = self.event_entry(event_handle) else {
            return NtStatus::INVALID_HANDLE;
        };
        let query = entry.with_entry(|entry| {
            entry
                .granted_access
                .require(EventAccess::QUERY_STATE)
                .map(|()| entry.event.query())
        });
        let info = match query {
            Ok(info) => info,
            Err(status) => return status,
        };
        if event_information.write_at_offset(0, info).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if let Some(return_length) = return_length
            && return_length
                .write_at_offset(0, EVENT_BASIC_INFORMATION_SIZE_U32)
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn modify_event(
        &self,
        event_handle: Handle,
        previous_state: Option<MutPtr<Platform, i32>>,
        op: impl FnOnce(&EventObject<Platform>) -> i32,
    ) -> NtStatus {
        let Ok(entry) = self.event_entry(event_handle) else {
            return NtStatus::INVALID_HANDLE;
        };
        let previous = entry.with_entry(|entry| {
            entry
                .granted_access
                .require(EventAccess::MODIFY_STATE)
                .map(|()| op(&entry.event))
        });
        let previous = match previous {
            Ok(previous) => previous,
            Err(status) => return status,
        };
        if let Some(previous_state) = previous_state
            && previous_state.write_at_offset(0, previous).is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::mem::size_of;

    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, UnicodeString};
    use crate::tests::{const_ptr, mut_ptr, test_task};

    const EVENT_QUERY_STATE: u32 = 0x0001;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const EVENT_ALL_ACCESS: u32 = 0x001f_0003;

    fn event_basic_information_size() -> u32 {
        u32::try_from(size_of::<EventBasicInformation>())
            .expect("EVENT_BASIC_INFORMATION fits in ULONG")
    }

    fn object_attributes_size() -> u32 {
        u32::try_from(size_of::<ObjectAttributes>()).expect("OBJECT_ATTRIBUTES fits in ULONG")
    }

    fn unicode_byte_len(units: &[u16]) -> u16 {
        u16::try_from(core::mem::size_of_val(units)).expect("test name fits in USHORT")
    }

    #[test]
    fn create_rejects_invalid_event_type() {
        let task = test_task();
        let mut handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            task.sys_nt_create_event(mut_ptr(&mut handle), EVENT_ALL_ACCESS, None, 2, 0),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
    }

    #[test]
    fn set_reset_clear_pulse_return_previous_state() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );

        let mut previous = -1;
        assert_eq!(
            task.sys_nt_set_event(handle, Some(mut_ptr(&mut previous))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous, 0);
        assert_eq!(
            task.sys_nt_set_event(handle, Some(mut_ptr(&mut previous))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous, 1);
        assert_eq!(
            task.sys_nt_reset_event(handle, Some(mut_ptr(&mut previous))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous, 1);
        assert_eq!(
            task.sys_nt_reset_event(handle, Some(mut_ptr(&mut previous))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous, 0);

        assert_eq!(task.sys_nt_set_event(handle, None), NtStatus::SUCCESS);
        assert_eq!(task.sys_nt_clear_event(handle), NtStatus::SUCCESS);
        assert_eq!(
            task.sys_nt_pulse_event(handle, Some(mut_ptr(&mut previous))),
            NtStatus::SUCCESS
        );
        assert_eq!(previous, 0);
    }

    #[test]
    fn query_event_reports_type_state_and_return_length() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Synchronization.as_raw(),
                1,
            ),
            NtStatus::SUCCESS
        );

        let mut info = EventBasicInformation {
            event_type: 99,
            event_state: -1,
        };
        let mut return_length = 0;
        assert_eq!(
            task.sys_nt_query_event(
                handle,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut info),
                event_basic_information_size(),
                Some(mut_ptr(&mut return_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            info,
            EventBasicInformation {
                event_type: EventType::Synchronization.as_raw(),
                event_state: 1,
            }
        );
        assert_eq!(return_length, event_basic_information_size());
    }

    #[test]
    fn query_validates_class_and_exact_length() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );
        let mut info = EventBasicInformation {
            event_type: 0,
            event_state: 0,
        };

        assert_eq!(
            task.sys_nt_query_event(
                handle,
                1,
                mut_ptr(&mut info),
                event_basic_information_size(),
                None,
            ),
            NtStatus::INVALID_INFO_CLASS
        );
        assert_eq!(
            task.sys_nt_query_event(
                handle,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut info),
                event_basic_information_size() - 1,
                None,
            ),
            NtStatus::INFO_LENGTH_MISMATCH
        );
    }

    #[test]
    fn handle_access_is_enforced() {
        let task = test_task();
        let mut query_only = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut query_only),
                EVENT_QUERY_STATE,
                None,
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );
        let mut modify_only = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut modify_only),
                EVENT_MODIFY_STATE,
                None,
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            task.sys_nt_set_event(query_only, None),
            NtStatus::ACCESS_DENIED
        );

        let mut info = EventBasicInformation {
            event_type: 0,
            event_state: 0,
        };
        assert_eq!(
            task.sys_nt_query_event(
                modify_only,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut info),
                event_basic_information_size(),
                None,
            ),
            NtStatus::ACCESS_DENIED
        );
    }

    #[test]
    fn named_event_open_shares_state() {
        let task = test_task();
        let mut name_units: Vec<u16> = "\\BaseNamedObjects\\LiteBoxEvent".encode_utf16().collect();
        let name = UnicodeString {
            length: unicode_byte_len(&name_units),
            maximum_length: unicode_byte_len(&name_units),
            padding_0: [0; 4],
            buffer: name_units.as_mut_ptr() as usize,
        };
        let attrs = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(&name) as usize,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        let mut created = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut created),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );

        let mut opened = Handle::default();
        assert_eq!(
            task.sys_nt_open_event(
                mut_ptr(&mut opened),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs))
            ),
            NtStatus::SUCCESS
        );
        assert_ne!(created, opened);

        assert_eq!(task.sys_nt_set_event(created, None), NtStatus::SUCCESS);
        let mut info = EventBasicInformation {
            event_type: 0,
            event_state: 0,
        };
        assert_eq!(
            task.sys_nt_query_event(
                opened,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut info),
                event_basic_information_size(),
                None,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(info.event_state, 1);
    }

    #[test]
    fn open_event_requires_existing_name() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_event(mut_ptr(&mut handle), EVENT_ALL_ACCESS, None),
            NtStatus::INVALID_PARAMETER
        );

        let unnamed_attrs = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        assert_eq!(
            task.sys_nt_open_event(
                mut_ptr(&mut handle),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&unnamed_attrs)),
            ),
            NtStatus::OBJECT_NAME_INVALID
        );
    }

    #[test]
    fn create_openif_existing_named_event_returns_name_exists() {
        let task = test_task();
        let mut name_units: Vec<u16> = "\\BaseNamedObjects\\LiteBoxOpenIf".encode_utf16().collect();
        let name = UnicodeString {
            length: unicode_byte_len(&name_units),
            maximum_length: unicode_byte_len(&name_units),
            padding_0: [0; 4],
            buffer: name_units.as_mut_ptr() as usize,
        };
        let attrs = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::default(),
            object_name: core::ptr::from_ref(&name) as usize,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        let openif_attrs = ObjectAttributes {
            attributes: OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
            ..attrs
        };

        let mut first = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut first),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );
        let mut collision = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut collision),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::OBJECT_NAME_COLLISION
        );
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut collision),
                EVENT_MODIFY_STATE,
                Some(const_ptr(&openif_attrs)),
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::OBJECT_NAME_EXISTS
        );
        assert_eq!(task.sys_nt_set_event(collision, None), NtStatus::SUCCESS);
    }

    #[test]
    fn close_invalidates_event_handle() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Notification.as_raw(),
                0,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        assert_eq!(
            task.sys_nt_set_event(handle, None),
            NtStatus::INVALID_HANDLE
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_create_query_reset_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const c_void,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtQueryEvent(
                handle: *mut c_void,
                event_information_class: u32,
                event_information: *mut EventBasicInformation,
                event_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
            fn NtResetEvent(handle: *mut c_void, previous_state: *mut i32) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let mut host_handle = core::ptr::null_mut();
        let mut host_info = EventBasicInformation {
            event_type: 0,
            event_state: 0,
        };
        let mut host_length = 0;
        let mut host_previous = 0;
        // SAFETY: The imported ntdll routines are called with valid output pointers, a null
        // object-attributes pointer accepted by NtCreateEvent, and the created host handle is
        // closed before leaving the test.
        unsafe {
            assert_eq!(
                NtCreateEvent(
                    &raw mut host_handle,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    EventType::Notification.as_raw(),
                    1,
                ),
                NtStatus::SUCCESS.as_raw()
            );
            assert_eq!(
                NtQueryEvent(
                    host_handle,
                    EventInformationClass::Basic as u32,
                    &raw mut host_info,
                    event_basic_information_size(),
                    &raw mut host_length,
                ),
                NtStatus::SUCCESS.as_raw()
            );
            assert_eq!(
                NtResetEvent(host_handle, &raw mut host_previous),
                NtStatus::SUCCESS.as_raw()
            );
            assert_eq!(NtClose(host_handle), NtStatus::SUCCESS.as_raw());
        }

        let task = test_task();
        let mut shim_handle = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut shim_handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Notification.as_raw(),
                1,
            ),
            NtStatus::SUCCESS
        );
        let mut shim_info = EventBasicInformation {
            event_type: 0,
            event_state: 0,
        };
        let mut shim_length = 0;
        let mut shim_previous = 0;
        assert_eq!(
            task.sys_nt_query_event(
                shim_handle,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut shim_info),
                event_basic_information_size(),
                Some(mut_ptr(&mut shim_length)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_reset_event(shim_handle, Some(mut_ptr(&mut shim_previous))),
            NtStatus::SUCCESS
        );

        assert_eq!(shim_info, host_info);
        assert_eq!(shim_length, host_length);
        assert_eq!(shim_previous, host_previous);
    }
}
