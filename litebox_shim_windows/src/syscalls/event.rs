// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT event object syscalls.

use alloc::sync::{Arc, Weak};
use core::marker::PhantomData;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::event::{Events, IOPollable, observer::Observer, polling::Pollee};
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::{
    AccessMask, ObjectAttributes, ObjectAttributesFlags, UnicodeString, read_object_attributes,
};
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value, raw_handle_entry,
};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
pub(crate) enum EventType {
    Notification = 0,
    Synchronization = 1,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct EventBasicInformation {
    event_type: u32,
    event_state: i32,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum EventInformationClass {
    Basic = 0,
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
        Self::from_bits_retain(AccessMask::expand_generic_access(
            desired_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        ))
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

    fn set_boost_priority(&self) -> Result<i32, NtStatus> {
        if self.event_type != EventType::Synchronization {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        }
        Ok(self.set())
    }

    fn reset(&self) -> i32 {
        self.replace_state(false)
    }

    fn clear(&self) -> i32 {
        self.replace_state(false)
    }

    fn pulse(&self) -> i32 {
        let previous = self.replace_state(true);
        self.pollee.notify_observers(Events::IN);
        self.replace_state(false);
        previous
    }

    fn query(&self) -> EventBasicInformation {
        EventBasicInformation {
            event_type: self.event_type as u32,
            event_state: i32::from(*self.signaled.lock()),
        }
    }

    pub(crate) fn is_signaled(&self) -> bool {
        *self.signaled.lock()
    }

    fn replace_state(&self, next: bool) -> i32 {
        let mut signaled = self.signaled.lock();
        let previous = i32::from(*signaled);
        *signaled = next;
        previous
    }
}

impl<Platform: crate::ShimPlatform> EventHandleObject<Platform> {
    pub(crate) fn require_access(&self, required: EventAccess) -> Result<(), NtStatus> {
        self.granted_access.require(required)
    }

    pub(crate) fn is_signaled(&self) -> bool {
        self.event.is_signaled()
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
    original_path: alloc::string::String,
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
    let original_path = unicode_string.read_string::<Platform>()?;
    if original_path.is_empty() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(Some(EventName { original_path }))
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
    if ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
        .contains(ObjectAttributesFlags::OPENLINK)
    {
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
        self.insert_typed_handle::<EventSubsystem<Platform>>(
            EventHandleObject {
                event,
                granted_access,
            },
            drop,
        )
    }

    pub(crate) fn close_event_handle(&self, handle: Handle) {
        self.close_typed_handle::<EventSubsystem<Platform>>(handle, drop);
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
        let Ok(event_type) = EventType::try_from(event_type) else {
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
            let event = Arc::new(EventObject::new(event_type, initial_state != 0));
            return self.process.object_manager.create_event(
                &event_name.original_path,
                &event,
                |event| {
                    let Some(object_attributes) = object_attributes else {
                        return NtStatus::INVALID_PARAMETER;
                    };
                    if !ObjectAttributesFlags::from_bits_retain(object_attributes.attributes)
                        .contains(ObjectAttributesFlags::OPENIF)
                    {
                        return NtStatus::OBJECT_NAME_COLLISION;
                    }
                    let Ok(handle) = self.insert_event_handle(event, granted_access) else {
                        return NtStatus::QUOTA_EXCEEDED;
                    };
                    if event_handle.write_at_offset(0, handle).is_none() {
                        self.close_event_handle(handle);
                        return NtStatus::ACCESS_VIOLATION;
                    }
                    NtStatus::OBJECT_NAME_EXISTS
                },
                || {
                    let Ok(handle) = self.insert_event_handle(event.clone(), granted_access) else {
                        return NtStatus::QUOTA_EXCEEDED;
                    };
                    if event_handle.write_at_offset(0, handle).is_none() {
                        self.close_event_handle(handle);
                        return NtStatus::ACCESS_VIOLATION;
                    }
                    NtStatus::SUCCESS
                },
            );
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
        let event = match self
            .process
            .object_manager
            .resolve_event(&event_name.original_path)
        {
            Ok(event) => event,
            Err(status) => return status,
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

        match self.modify_event(event_handle, previous_state, |event| Ok(event.set())) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
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

        match self.modify_event(event_handle, previous_state, |event| Ok(event.reset())) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    pub(crate) fn sys_nt_clear_event(&self, event_handle: Handle) -> NtStatus {
        match self.modify_event(event_handle, None, |event| Ok(event.clear())) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
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

        match self.modify_event(event_handle, previous_state, |event| Ok(event.pulse())) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
    }

    pub(crate) fn sys_nt_set_event_boost_priority(&self, event_handle: Handle) -> NtStatus {
        match self.modify_event(event_handle, None, EventObject::set_boost_priority) {
            Ok(()) => NtStatus::SUCCESS,
            Err(status) => status,
        }
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
            EventInformationClass::try_from(event_information_class)
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
        op: impl FnOnce(&EventObject<Platform>) -> Result<i32, NtStatus>,
    ) -> Result<(), NtStatus> {
        let entry = self.event_entry(event_handle)?;
        let previous = entry.with_entry(|entry| {
            entry.granted_access.require(EventAccess::MODIFY_STATE)?;
            op(&entry.event)
        })?;
        if let Some(previous_state) = previous_state
            && previous_state.write_at_offset(0, previous).is_none()
        {
            return Err(NtStatus::ACCESS_VIOLATION);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::utils::TruncateExt as _;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::{ObjectAttributes, ObjectAttributesFlags};
    use crate::tests::{
        const_ptr, mut_ptr, object_attributes, test_task, unicode_string, utf16_units,
    };

    const EVENT_QUERY_STATE: u32 = 0x0001;
    const EVENT_MODIFY_STATE: u32 = 0x0002;
    const EVENT_ALL_ACCESS: u32 = 0x001f_0003;

    fn event_basic_information_size() -> u32 {
        size_of::<EventBasicInformation>().trunc()
    }

    fn object_attributes_size() -> u32 {
        size_of::<ObjectAttributes>().trunc()
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
                EventType::Notification as u32,
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
                EventType::Synchronization as u32,
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
                event_type: EventType::Synchronization as u32,
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
                EventType::Notification as u32,
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
                EventType::Notification as u32,
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
                EventType::Notification as u32,
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
        let name_units = utf16_units("\\BaseNamedObjects\\LiteBoxEvent");
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());

        let mut created = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut created),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                EventType::Notification as u32,
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
        let name_units = utf16_units("\\BaseNamedObjects\\LiteBoxOpenIf");
        let name = unicode_string(&name_units);
        let attrs = object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());
        let openif_attrs = ObjectAttributes {
            attributes: (ObjectAttributesFlags::CASE_INSENSITIVE | ObjectAttributesFlags::OPENIF)
                .bits(),
            ..attrs
        };

        let mut first = Handle::default();
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut first),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attrs)),
                EventType::Notification as u32,
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
                EventType::Notification as u32,
                0,
            ),
            NtStatus::OBJECT_NAME_COLLISION
        );
        assert_eq!(
            task.sys_nt_create_event(
                mut_ptr(&mut collision),
                EVENT_MODIFY_STATE,
                Some(const_ptr(&openif_attrs)),
                EventType::Notification as u32,
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
                EventType::Notification as u32,
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
    mod host_fidelity {
        use core::ffi::c_void;

        use super::*;

        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtOpenEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
            ) -> i32;
            fn NtSetEvent(handle: *mut c_void, previous_state: *mut i32) -> i32;
            fn NtResetEvent(handle: *mut c_void, previous_state: *mut i32) -> i32;
            fn NtClearEvent(handle: *mut c_void) -> i32;
            fn NtPulseEvent(handle: *mut c_void, previous_state: *mut i32) -> i32;
            fn NtSetEventBoostPriority(handle: *mut c_void) -> i32;
            fn NtQueryEvent(
                handle: *mut c_void,
                event_information_class: u32,
                event_information: *mut EventBasicInformation,
                event_information_length: u32,
                return_length: *mut u32,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        fn assert_status_eq(shim: NtStatus, host: i32) {
            assert_eq!(shim.as_raw(), host);
        }

        fn close_host_handle(handle: *mut c_void) {
            if !handle.is_null() {
                // SAFETY: The handle was returned by a successful host ntdll call in this test.
                let status = unsafe { NtClose(handle) };
                assert_eq!(status, NtStatus::SUCCESS.as_raw());
            }
        }

        fn host_query_event(handle: *mut c_void) -> (i32, EventBasicInformation, u32) {
            let mut info = EventBasicInformation {
                event_type: 0,
                event_state: 0,
            };
            let mut return_length = 0;
            // SAFETY: `handle` is a live host event handle and the output pointers reference
            // stack locals that are valid for the duration of the call.
            let status = unsafe {
                NtQueryEvent(
                    handle,
                    EventInformationClass::Basic as u32,
                    &raw mut info,
                    event_basic_information_size(),
                    &raw mut return_length,
                )
            };
            (status, info, return_length)
        }

        fn shim_query_event(
            task: &Task<crate::tests::TestPlatform, crate::tests::TestFS>,
            handle: Handle,
        ) -> (NtStatus, EventBasicInformation, u32) {
            let mut info = EventBasicInformation {
                event_type: 0,
                event_state: 0,
            };
            let mut return_length = 0;
            let status = task.sys_nt_query_event(
                handle,
                EventInformationClass::Basic as u32,
                mut_ptr(&mut info),
                event_basic_information_size(),
                Some(mut_ptr(&mut return_length)),
            );
            (status, info, return_length)
        }

        fn assert_queries_match(
            task: &Task<crate::tests::TestPlatform, crate::tests::TestFS>,
            host_handle: *mut c_void,
            shim_handle: Handle,
        ) {
            let (host_status, host_info, host_length) = host_query_event(host_handle);
            let (shim_status, shim_info, shim_length) = shim_query_event(task, shim_handle);
            assert_status_eq(shim_status, host_status);
            assert_eq!(shim_info, host_info);
            assert_eq!(shim_length, host_length);
        }

        #[test]
        fn create_query_reset_matches_host_outputs() {
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The output pointer references a live stack local, null object attributes are
            // accepted by NtCreateEvent, and the handle is closed before the test returns.
            let host_create_status = unsafe {
                NtCreateEvent(
                    &raw mut host_handle,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    EventType::Notification as u32,
                    1,
                )
            };
            assert_eq!(host_create_status, NtStatus::SUCCESS.as_raw());
            let (host_query_status, host_info, host_length) = host_query_event(host_handle);
            assert_eq!(host_query_status, NtStatus::SUCCESS.as_raw());
            let mut host_previous = 0;
            // SAFETY: `host_handle` is a live event handle and `host_previous` is a valid output.
            let host_reset_status = unsafe { NtResetEvent(host_handle, &raw mut host_previous) };

            let task = test_task();
            let mut shim_handle = Handle::default();
            let shim_create_status = task.sys_nt_create_event(
                mut_ptr(&mut shim_handle),
                EVENT_ALL_ACCESS,
                None,
                EventType::Notification as u32,
                1,
            );
            assert_status_eq(shim_create_status, host_create_status);
            let (shim_query_status, shim_info, shim_length) = shim_query_event(&task, shim_handle);
            assert_status_eq(shim_query_status, host_query_status);
            let mut shim_previous = 0;
            let shim_reset_status =
                task.sys_nt_reset_event(shim_handle, Some(mut_ptr(&mut shim_previous)));

            assert_status_eq(shim_reset_status, host_reset_status);
            assert_eq!(shim_info, host_info);
            assert_eq!(shim_length, host_length);
            assert_eq!(shim_previous, host_previous);

            close_host_handle(host_handle);
        }

        #[test]
        fn set_clear_pulse_and_boost_match_host_state() {
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The output pointer references a live stack local, null object attributes are
            // accepted by NtCreateEvent, and the handle is closed before the test returns.
            let status = unsafe {
                NtCreateEvent(
                    &raw mut host_handle,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    EventType::Notification as u32,
                    0,
                )
            };
            assert_eq!(status, NtStatus::SUCCESS.as_raw());

            let task = test_task();
            let mut shim_handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_event(
                    mut_ptr(&mut shim_handle),
                    EVENT_ALL_ACCESS,
                    None,
                    EventType::Notification as u32,
                    0,
                ),
                NtStatus::SUCCESS
            );

            let mut host_previous = -1;
            let mut shim_previous = -1;
            // SAFETY: `host_handle` is a live event handle and `host_previous` is a valid output.
            let host_status = unsafe { NtSetEvent(host_handle, &raw mut host_previous) };
            let shim_status = task.sys_nt_set_event(shim_handle, Some(mut_ptr(&mut shim_previous)));
            assert_status_eq(shim_status, host_status);
            assert_eq!(shim_previous, host_previous);
            assert_queries_match(&task, host_handle, shim_handle);

            // SAFETY: `host_handle` is a live event handle.
            let host_status = unsafe { NtClearEvent(host_handle) };
            let shim_status = task.sys_nt_clear_event(shim_handle);
            assert_status_eq(shim_status, host_status);
            assert_queries_match(&task, host_handle, shim_handle);

            host_previous = -1;
            shim_previous = -1;
            // SAFETY: `host_handle` is a live event handle and `host_previous` is a valid output.
            let host_status = unsafe { NtPulseEvent(host_handle, &raw mut host_previous) };
            let shim_status =
                task.sys_nt_pulse_event(shim_handle, Some(mut_ptr(&mut shim_previous)));
            assert_status_eq(shim_status, host_status);
            assert_eq!(shim_previous, host_previous);
            assert_queries_match(&task, host_handle, shim_handle);

            // SAFETY: `host_handle` is a live event handle.
            let host_status = unsafe { NtSetEventBoostPriority(host_handle) };
            let shim_status = task.sys_nt_set_event_boost_priority(shim_handle);
            assert_status_eq(shim_status, host_status);
            assert_queries_match(&task, host_handle, shim_handle);

            close_host_handle(host_handle);
        }

        #[test]
        fn boost_priority_sets_synchronization_event() {
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The output pointer references a live stack local, null object attributes are
            // accepted by NtCreateEvent, and the handle is closed before the test returns.
            let status = unsafe {
                NtCreateEvent(
                    &raw mut host_handle,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    EventType::Synchronization as u32,
                    0,
                )
            };
            assert_eq!(status, NtStatus::SUCCESS.as_raw());

            let task = test_task();
            let mut shim_handle = Handle::default();
            assert_eq!(
                task.sys_nt_create_event(
                    mut_ptr(&mut shim_handle),
                    EVENT_ALL_ACCESS,
                    None,
                    EventType::Synchronization as u32,
                    0,
                ),
                NtStatus::SUCCESS
            );

            // SAFETY: `host_handle` is a live synchronization event handle.
            let host_status = unsafe { NtSetEventBoostPriority(host_handle) };
            let shim_status = task.sys_nt_set_event_boost_priority(shim_handle);
            assert_status_eq(shim_status, host_status);
            assert_queries_match(&task, host_handle, shim_handle);

            close_host_handle(host_handle);
        }

        #[test]
        fn named_open_matches_host_state_sharing() {
            let unique = 0u8;
            let name_units = utf16_units(&alloc::format!(
                r"\BaseNamedObjects\LiteBoxEventFidelity{:p}",
                &unique,
            ));
            let name = unicode_string(&name_units);
            let attributes =
                object_attributes(&name, ObjectAttributesFlags::CASE_INSENSITIVE.bits());

            let mut host_created = core::ptr::null_mut();
            let mut host_opened = core::ptr::null_mut();
            // SAFETY: Pointers reference live stack locals and ObjectAttributes points to a live
            // UnicodeString naming a BaseNamedObjects event for the duration of the calls.
            let host_create_status = unsafe {
                NtCreateEvent(
                    &raw mut host_created,
                    EVENT_ALL_ACCESS,
                    &raw const attributes,
                    EventType::Notification as u32,
                    0,
                )
            };
            assert_eq!(host_create_status, NtStatus::SUCCESS.as_raw());
            // SAFETY: Same live ObjectAttributes as above, and output pointer is valid.
            let host_open_status = unsafe {
                NtOpenEvent(
                    &raw mut host_opened,
                    EVENT_MODIFY_STATE,
                    &raw const attributes,
                )
            };
            assert_eq!(host_open_status, NtStatus::SUCCESS.as_raw());

            let task = test_task();
            let mut shim_created = Handle::default();
            let shim_create_status = task.sys_nt_create_event(
                mut_ptr(&mut shim_created),
                EVENT_ALL_ACCESS,
                Some(const_ptr(&attributes)),
                EventType::Notification as u32,
                0,
            );
            assert_status_eq(shim_create_status, host_create_status);
            let mut shim_opened = Handle::default();
            let shim_open_status = task.sys_nt_open_event(
                mut_ptr(&mut shim_opened),
                EVENT_MODIFY_STATE,
                Some(const_ptr(&attributes)),
            );
            assert_status_eq(shim_open_status, host_open_status);

            // SAFETY: `host_opened` is a live event handle opened with EVENT_MODIFY_STATE.
            let host_set_status = unsafe { NtSetEvent(host_opened, core::ptr::null_mut()) };
            let shim_set_status = task.sys_nt_set_event(shim_opened, None);
            assert_status_eq(shim_set_status, host_set_status);
            assert_queries_match(&task, host_created, shim_created);

            close_host_handle(host_opened);
            close_host_handle(host_created);
        }
    }
}
