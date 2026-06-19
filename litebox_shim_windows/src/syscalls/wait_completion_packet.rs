// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT wait completion packet syscalls.

use alloc::sync::Arc;
use core::marker::PhantomData;

use litebox::fd::{ErrRawIntFd, FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawMutPointer as _, RawPointerProvider};
use litebox::sync::Mutex;
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes, read_object_attributes};
use crate::syscalls::Handle;
use crate::syscalls::event::{EventAccess, EventSubsystem};
use crate::syscalls::iocp::{IoCompletionAccess, IoCompletionSubsystem};
use crate::syscalls::timer::{TimerAccess, TimerSubsystem};
use crate::{
    ConstPtr, MutPtr, ShimFS, Task, insert_raw_handle, probe_guest_output_preserving_value,
    remove_raw_handle,
};

const STANDARD_RIGHTS_REQUIRED: u32 = AccessMask::DELETE.bits()
    | AccessMask::READ_CONTROL.bits()
    | AccessMask::WRITE_DAC.bits()
    | AccessMask::WRITE_OWNER.bits();

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct WaitCompletionPacketAccess: u32 {
        const SET_STATE = 0x0001;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::SET_STATE.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits() | Self::SET_STATE.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits() | Self::SET_STATE.bits();
        const ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | Self::SET_STATE.bits();

        const _ = !0;
    }
}

impl WaitCompletionPacketAccess {
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

pub(crate) struct WaitCompletionPacketSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for WaitCompletionPacketSubsystem<Platform> {
    type Entry = WaitCompletionPacketHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry
    for WaitCompletionPacketHandleObject<Platform>
{
}

pub(crate) struct WaitCompletionPacketHandleObject<Platform: crate::ShimPlatform> {
    packet: Arc<WaitCompletionPacketObject<Platform>>,
    granted_access: WaitCompletionPacketAccess,
}

pub(crate) struct WaitCompletionPacketObject<Platform: crate::ShimPlatform> {
    association: Mutex<Platform, Option<WaitCompletionPacketAssociation>>,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WaitCompletionPacketAssociation {
    _key_context: usize,
    _apc_context: usize,
    _io_status: i32,
    _io_status_information: usize,
    already_signaled: bool,
}

pub(crate) struct WaitCompletionPacketAssociateParameters<Platform: RawPointerProvider> {
    pub(crate) wait_completion_packet_handle: Handle,
    pub(crate) io_completion_handle: Handle,
    pub(crate) target_object_handle: Handle,
    pub(crate) key_context: usize,
    pub(crate) apc_context: usize,
    pub(crate) io_status: i32,
    pub(crate) io_status_information: usize,
    pub(crate) already_signaled: Option<MutPtr<Platform, u8>>,
}

fn validate_wait_completion_packet_object_attributes<Platform: RawPointerProvider>(
    object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
) -> Result<(), NtStatus> {
    let Some(object_attributes) = object_attributes else {
        return Ok(());
    };
    let object_attributes = read_object_attributes::<Platform>(object_attributes)?;
    if object_attributes.object_name == 0 && !object_attributes.root_directory.is_null() {
        return Err(NtStatus::OBJECT_NAME_INVALID);
    }
    Ok(())
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn wait_completion_packet_entry(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, WaitCompletionPacketSubsystem<Platform>>, NtStatus>
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<WaitCompletionPacketSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound | ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::OBJECT_TYPE_MISMATCH)
    }

    fn wait_completion_packet_entry_for_cancel(
        &self,
        handle: Handle,
    ) -> Result<litebox::fd::EntryHandle<Platform, WaitCompletionPacketSubsystem<Platform>>, NtStatus>
    {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::INVALID_HANDLE);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<WaitCompletionPacketSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::INVALID_HANDLE),
                Err(ErrRawIntFd::InvalidSubsystem) => return Err(NtStatus::OBJECT_TYPE_MISMATCH),
            }
        };
        self.global
            .litebox
            .descriptor_table()
            .entry_handle(&typed)
            .ok_or(NtStatus::INVALID_HANDLE)
    }

    fn validate_io_completion_for_wait_completion_packet(
        &self,
        handle: Handle,
    ) -> Result<(), NtStatus> {
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<IoCompletionSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound | ErrRawIntFd::InvalidSubsystem) => {
                    return Err(NtStatus::OBJECT_TYPE_MISMATCH);
                }
            }
        };
        let Some(entry) = self.global.litebox.descriptor_table().entry_handle(&typed) else {
            return Err(NtStatus::OBJECT_TYPE_MISMATCH);
        };
        entry.with_entry(|entry| entry.require_access(IoCompletionAccess::MODIFY_STATE))
    }

    fn target_object_signaled_for_wait_completion_packet(
        &self,
        handle: Handle,
    ) -> Result<bool, NtStatus> {
        // TODO: support every waitable target object type that Windows accepts here; the
        // current subset only recognizes event and timer handles.
        let Some(raw_fd) = handle.raw_fd() else {
            return Err(NtStatus::ACCESS_DENIED);
        };
        if let Some(signaled) = self.event_signaled_for_wait_completion_packet(raw_fd)? {
            return Ok(signaled);
        }
        if let Some(signaled) = self.timer_signaled_for_wait_completion_packet(raw_fd)? {
            return Ok(signaled);
        }
        Err(NtStatus::INVALID_PARAMETER_3)
    }

    fn event_signaled_for_wait_completion_packet(
        &self,
        raw_fd: usize,
    ) -> Result<Option<bool>, NtStatus> {
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<EventSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::ACCESS_DENIED),
                Err(ErrRawIntFd::InvalidSubsystem) => return Ok(None),
            }
        };
        let Some(entry) = self.global.litebox.descriptor_table().entry_handle(&typed) else {
            return Err(NtStatus::ACCESS_DENIED);
        };
        entry
            .with_entry(|entry| {
                entry
                    .require_access(EventAccess::from_bits_retain(
                        AccessMask::SYNCHRONIZE.bits(),
                    ))
                    .map(|()| entry.is_signaled())
            })
            .map(Some)
    }

    fn timer_signaled_for_wait_completion_packet(
        &self,
        raw_fd: usize,
    ) -> Result<Option<bool>, NtStatus> {
        let typed = {
            let handles = self.process.handles.read();
            match handles.fd_from_raw_integer::<TimerSubsystem<Platform>>(raw_fd) {
                Ok(typed) => typed,
                Err(ErrRawIntFd::NotFound) => return Err(NtStatus::ACCESS_DENIED),
                Err(ErrRawIntFd::InvalidSubsystem) => return Ok(None),
            }
        };
        let Some(entry) = self.global.litebox.descriptor_table().entry_handle(&typed) else {
            return Err(NtStatus::ACCESS_DENIED);
        };
        // TODO: return the timer object's real signaled state after NtSetTimer2 models
        // due-time expiration and periodic re-signaling.
        entry
            .with_entry(|entry| {
                entry
                    .require_access(TimerAccess::from_bits_retain(
                        AccessMask::SYNCHRONIZE.bits(),
                    ))
                    .map(|()| false)
            })
            .map(Some)
    }

    fn insert_wait_completion_packet_handle(
        &self,
        packet: Arc<WaitCompletionPacketObject<Platform>>,
        granted_access: WaitCompletionPacketAccess,
    ) -> Result<Handle, NtStatus> {
        let typed = self
            .global
            .litebox
            .descriptor_table_mut()
            .insert::<WaitCompletionPacketSubsystem<Platform>>(WaitCompletionPacketHandleObject {
                packet,
                granted_access,
            });
        insert_raw_handle::<Platform, WaitCompletionPacketSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            typed,
            drop,
        )
    }

    pub(crate) fn close_wait_completion_packet_handle(&self, handle: Handle) {
        remove_raw_handle::<Platform, WaitCompletionPacketSubsystem<Platform>>(
            &self.global.litebox,
            &self.process.handles,
            handle,
            drop,
        );
    }

    pub(crate) fn close_wait_completion_packet(
        wait_completion_packet: WaitCompletionPacketHandleObject<Platform>,
    ) {
        drop(wait_completion_packet);
    }

    pub(crate) fn sys_nt_create_wait_completion_packet(
        &self,
        wait_completion_packet_handle: MutPtr<Platform, Handle>,
        desired_access: u32,
        object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    ) -> NtStatus {
        if let Err(status) =
            probe_guest_output_preserving_value::<Platform, _>(wait_completion_packet_handle)
        {
            return status;
        }
        if let Err(status) =
            validate_wait_completion_packet_object_attributes::<Platform>(object_attributes)
        {
            return status;
        }

        let packet = Arc::new(WaitCompletionPacketObject {
            association: Mutex::new(None),
            _not_send_without_platform: PhantomData,
        });
        let granted_access = WaitCompletionPacketAccess::from_desired_access(desired_access);
        let Ok(handle) = self.insert_wait_completion_packet_handle(packet, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if wait_completion_packet_handle
            .write_at_offset(0, handle)
            .is_none()
        {
            self.close_wait_completion_packet_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_associate_wait_completion_packet(
        &self,
        params: WaitCompletionPacketAssociateParameters<Platform>,
    ) -> NtStatus {
        let entry = match self.wait_completion_packet_entry(params.wait_completion_packet_handle) {
            Ok(entry) => entry,
            Err(status) => return status,
        };
        let packet = match entry.with_entry(|entry| {
            entry
                .granted_access
                .require(WaitCompletionPacketAccess::SET_STATE)
                .map(|()| entry.packet.clone())
        }) {
            Ok(packet) => packet,
            Err(status) => return status,
        };

        if let Err(status) =
            self.validate_io_completion_for_wait_completion_packet(params.io_completion_handle)
        {
            return status;
        }
        {
            let association = packet.association.lock();
            if association.is_some() {
                return NtStatus::INVALID_PARAMETER_1;
            }
        }
        let already_signaled = match self
            .target_object_signaled_for_wait_completion_packet(params.target_object_handle)
        {
            Ok(already_signaled) => already_signaled,
            Err(status) => return status,
        };
        if let Some(already_signaled_ptr) = params.already_signaled
            && already_signaled_ptr
                .write_at_offset(0, u8::from(already_signaled))
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }

        // TODO: link the packet into the target object's wait notification path and post to
        // the associated IOCP when the target is already signaled or becomes signaled later.
        let mut association = packet.association.lock();
        if association.is_some() {
            return NtStatus::INVALID_PARAMETER_1;
        }
        *association = Some(WaitCompletionPacketAssociation {
            _key_context: params.key_context,
            _apc_context: params.apc_context,
            _io_status: params.io_status,
            _io_status_information: params.io_status_information,
            already_signaled,
        });
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_cancel_wait_completion_packet(
        &self,
        wait_completion_packet_handle: Handle,
        remove_signaled_packet: u8,
    ) -> NtStatus {
        let entry =
            match self.wait_completion_packet_entry_for_cancel(wait_completion_packet_handle) {
                Ok(entry) => entry,
                Err(status) => return status,
            };
        let packet = match entry.with_entry(|entry| {
            entry
                .granted_access
                .require(WaitCompletionPacketAccess::SET_STATE)
                .map(|()| Arc::clone(&entry.packet))
        }) {
            Ok(packet) => packet,
            Err(status) => return status,
        };

        let mut association = packet.association.lock();
        let Some(current_association) = *association else {
            return NtStatus::CANCELLED;
        };
        if current_association.already_signaled && remove_signaled_packet == 0 {
            return NtStatus::PENDING;
        }

        // TODO: if a signaled packet has been posted to the IOCP, honor
        // remove_signaled_packet by removing that queued completion packet.
        *association = None;
        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::{RawConstPointer as _, ThreadProvider};
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributes;
    use crate::tests::{TestPlatform, const_ptr, mut_ptr, test_platform, test_task};

    const WAIT_COMPLETION_PACKET_SET_STATE: u32 = 0x0000_0001;
    const WAIT_COMPLETION_PACKET_ALL_ACCESS: u32 = 0x000f_0001;
    const IO_COMPLETION_QUERY_STATE: u32 = 0x0000_0001;
    const IO_COMPLETION_ALL_ACCESS: u32 = 0x001f_0003;
    const EVENT_QUERY_STATE: u32 = 0x0000_0001;
    const EVENT_ALL_ACCESS: u32 = 0x001f_0003;
    const SYNCHRONIZE: u32 = 0x0010_0000;

    fn object_attributes_size() -> u32 {
        u32::try_from(size_of::<ObjectAttributes>()).expect("OBJECT_ATTRIBUTES fits in ULONG")
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn create_wait_completion_packet(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        object_attributes: Option<ConstPtr<TestPlatform, ObjectAttributes>>,
    ) -> NtStatus {
        task.sys_nt_create_wait_completion_packet(
            mut_ptr(handle),
            WAIT_COMPLETION_PACKET_ALL_ACCESS,
            object_attributes,
        )
    }

    fn create_wait_completion_packet_with_access(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        desired_access: u32,
    ) -> NtStatus {
        task.sys_nt_create_wait_completion_packet(mut_ptr(handle), desired_access, None)
    }

    fn create_io_completion(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        desired_access: u32,
    ) -> NtStatus {
        task.sys_nt_create_io_completion(mut_ptr(handle), desired_access, None, 0)
    }

    fn create_event(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        desired_access: u32,
        initial_state: bool,
    ) -> NtStatus {
        task.sys_nt_create_event(
            mut_ptr(handle),
            desired_access,
            None,
            0,
            u8::from(initial_state),
        )
    }

    fn create_timer(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        desired_access: u32,
    ) -> NtStatus {
        task.sys_nt_create_timer2(crate::syscalls::timer::TimerCreateParameters {
            timer_handle: mut_ptr(handle),
            timer_id: None,
            object_attributes: None,
            attributes: 0,
            desired_access,
        })
    }

    fn associate_wait_completion_packet(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        packet: Handle,
        io_completion: Handle,
        target: Handle,
        already_signaled: Option<MutPtr<TestPlatform, u8>>,
    ) -> NtStatus {
        task.sys_nt_associate_wait_completion_packet(WaitCompletionPacketAssociateParameters {
            wait_completion_packet_handle: packet,
            io_completion_handle: io_completion,
            target_object_handle: target,
            key_context: 0x1111,
            apc_context: 0x2222,
            io_status: NtStatus::SUCCESS.as_raw(),
            io_status_information: 0x3333,
            already_signaled,
        })
    }

    fn cancel_wait_completion_packet(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        packet: Handle,
        remove_signaled_packet: bool,
    ) -> NtStatus {
        task.sys_nt_cancel_wait_completion_packet(packet, u8::from(remove_signaled_packet))
    }

    #[test]
    fn create_validates_object_attributes_without_clobbering_output() {
        let task = test_task();
        let mut handle = Handle::from_raw(usize::MAX);
        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        assert_eq!(
            create_wait_completion_packet(&task, &mut handle, Some(const_ptr(&bad_length))),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));

        let root_without_name = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::from_raw(4),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        assert_eq!(
            create_wait_completion_packet(&task, &mut handle, Some(const_ptr(&root_without_name))),
            NtStatus::OBJECT_NAME_INVALID
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
    }

    #[test]
    fn associate_writes_signal_state_and_marks_packet_busy() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut event = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 0);

        already_signaled = 0xaa;
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::INVALID_PARAMETER_1
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                Handle::from_raw(0x1234),
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::INVALID_PARAMETER_1
        );
        assert_eq!(already_signaled, 0xaa);
    }

    #[test]
    fn associate_reports_already_signaled_target() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut event = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, true),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 1);
    }

    #[test]
    fn associate_accepts_timer_target_as_unsignaled() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut timer = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_timer(&task, &mut timer, SYNCHRONIZE),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                timer,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 0);
    }

    #[test]
    fn associate_invalid_already_signaled_does_not_commit_association() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let mut packet = Handle::default();
            let mut io_completion = Handle::default();
            let mut event = Handle::default();
            let mut already_signaled = 0xaa;

            assert_eq!(
                create_wait_completion_packet(&task, &mut packet, None),
                NtStatus::SUCCESS
            );
            assert_eq!(
                create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
                NtStatus::SUCCESS
            );
            assert_eq!(
                create_event(&task, &mut event, EVENT_ALL_ACCESS, true),
                NtStatus::SUCCESS
            );

            assert_eq!(
                associate_wait_completion_packet(
                    &task,
                    packet,
                    io_completion,
                    event,
                    Some(MutPtr::<TestPlatform, u8>::from_usize(1)),
                ),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                cancel_wait_completion_packet(&task, packet, true),
                NtStatus::CANCELLED
            );
            assert_eq!(
                associate_wait_completion_packet(
                    &task,
                    packet,
                    io_completion,
                    event,
                    Some(mut_ptr(&mut already_signaled)),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(already_signaled, 1);
        });
    }

    #[test]
    fn associate_enforces_native_observed_access_masks() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut packet_without_set_state = Handle::default();
        let mut io_completion = Handle::default();
        let mut io_completion_query_only = Handle::default();
        let mut event = Handle::default();
        let mut event_without_synchronize = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet_with_access(
                &task,
                &mut packet,
                WAIT_COMPLETION_PACKET_SET_STATE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_wait_completion_packet_with_access(&task, &mut packet_without_set_state, 0),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(
                &task,
                &mut io_completion_query_only,
                IO_COMPLETION_QUERY_STATE,
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, SYNCHRONIZE, false),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(
                &task,
                &mut event_without_synchronize,
                EVENT_QUERY_STATE,
                false,
            ),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet_without_set_state,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion_query_only,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event_without_synchronize,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 0);
    }

    #[test]
    fn associate_distinguishes_handle_errors_like_native_windows() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut target_io_completion = Handle::default();
        let mut event = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut target_io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                Handle::from_raw(0x1234),
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                Handle::from_raw(0x1234),
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                Handle::from_raw(0x1234),
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                target_io_completion,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::INVALID_PARAMETER_3
        );
        assert_eq!(already_signaled, 0xaa);
    }

    #[test]
    fn cancel_clears_unsignaled_association_and_allows_reuse() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut event = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );

        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, packet, false),
            NtStatus::SUCCESS
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, packet, false),
            NtStatus::CANCELLED
        );

        already_signaled = 0xaa;
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 0);
    }

    #[test]
    fn cancel_signaled_packet_obeys_remove_signaled_packet() {
        let task = test_task();
        let mut packet = Handle::default();
        let mut io_completion = Handle::default();
        let mut event = Handle::default();
        let mut already_signaled = 0xaa;

        assert_eq!(
            create_wait_completion_packet(&task, &mut packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_io_completion(&task, &mut io_completion, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, true),
            NtStatus::SUCCESS
        );
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(already_signaled, 1);

        assert_eq!(
            cancel_wait_completion_packet(&task, packet, false),
            NtStatus::PENDING
        );
        already_signaled = 0xaa;
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                packet,
                io_completion,
                event,
                Some(mut_ptr(&mut already_signaled)),
            ),
            NtStatus::INVALID_PARAMETER_1
        );
        assert_eq!(already_signaled, 0xaa);

        assert_eq!(
            cancel_wait_completion_packet(&task, packet, true),
            NtStatus::SUCCESS
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, packet, true),
            NtStatus::CANCELLED
        );
    }

    #[test]
    fn cancel_distinguishes_handle_errors_and_requires_set_state() {
        let task = test_task();
        let mut event = Handle::default();
        let mut packet_without_set_state = Handle::default();

        assert_eq!(
            create_event(&task, &mut event, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_wait_completion_packet_with_access(&task, &mut packet_without_set_state, 0),
            NtStatus::SUCCESS
        );

        assert_eq!(
            cancel_wait_completion_packet(&task, Handle::default(), false),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, Handle::from_raw(0x1234), true),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, event, false),
            NtStatus::OBJECT_TYPE_MISMATCH
        );
        assert_eq!(
            cancel_wait_completion_packet(&task, packet_without_set_state, false),
            NtStatus::ACCESS_DENIED
        );
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_cancel_wait_completion_packet_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateWaitCompletionPacket(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
            ) -> i32;
            fn NtCancelWaitCompletionPacket(handle: *mut c_void, remove_signaled_packet: u8)
            -> i32;
            fn NtAssociateWaitCompletionPacket(
                packet: *mut c_void,
                io_completion: *mut c_void,
                target: *mut c_void,
                key_context: *mut c_void,
                apc_context: *mut c_void,
                io_status: i32,
                io_status_information: usize,
                already_signaled: *mut u8,
            ) -> i32;
            fn NtCreateIoCompletion(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                number_of_concurrent_threads: u32,
            ) -> i32;
            fn NtCreateEvent(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
                event_type: u32,
                initial_state: u8,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        unsafe fn close_host(handle: *mut c_void) {
            if !handle.is_null() {
                // SAFETY: The caller passes a live host handle returned by an NtCreate* call.
                assert_eq!(unsafe { NtClose(handle) }, NtStatus::SUCCESS.as_raw());
            }
        }

        let task = test_task();

        // SAFETY: The null handle is an input-only value and no memory is dereferenced.
        let host_null = unsafe { NtCancelWaitCompletionPacket(core::ptr::null_mut(), 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, Handle::default(), false).as_raw(),
            host_null
        );

        let mut host_event = core::ptr::null_mut();
        // SAFETY: The output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateEvent(
                    &raw mut host_event,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    0,
                    0,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut shim_event = Handle::default();
        assert_eq!(
            create_event(&task, &mut shim_event, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );
        // SAFETY: The host event handle is valid for the duration of this call.
        let host_wrong_type = unsafe { NtCancelWaitCompletionPacket(host_event, 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_event, false).as_raw(),
            host_wrong_type
        );
        // SAFETY: The event handle was returned by NtCreateEvent in this test.
        unsafe { close_host(host_event) };

        let mut host_packet = core::ptr::null_mut();
        // SAFETY: The output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateWaitCompletionPacket(
                    &raw mut host_packet,
                    WAIT_COMPLETION_PACKET_ALL_ACCESS,
                    core::ptr::null(),
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut shim_packet = Handle::default();
        assert_eq!(
            create_wait_completion_packet(&task, &mut shim_packet, None),
            NtStatus::SUCCESS
        );
        // SAFETY: The host packet handle is valid for the duration of this call.
        let host_unassociated = unsafe { NtCancelWaitCompletionPacket(host_packet, 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_packet, false).as_raw(),
            host_unassociated
        );
        // SAFETY: The packet handle was returned by NtCreateWaitCompletionPacket in this test.
        unsafe { close_host(host_packet) };

        let mut host_packet_no_set = core::ptr::null_mut();
        // SAFETY: The output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateWaitCompletionPacket(&raw mut host_packet_no_set, 0, core::ptr::null())
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut shim_packet_no_set = Handle::default();
        assert_eq!(
            create_wait_completion_packet_with_access(&task, &mut shim_packet_no_set, 0),
            NtStatus::SUCCESS
        );
        // SAFETY: The host packet handle is valid for the duration of this call.
        let host_no_set = unsafe { NtCancelWaitCompletionPacket(host_packet_no_set, 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_packet_no_set, false).as_raw(),
            host_no_set
        );
        // SAFETY: The packet handle was returned by NtCreateWaitCompletionPacket in this test.
        unsafe { close_host(host_packet_no_set) };

        let mut host_iocp = core::ptr::null_mut();
        let mut host_assoc_packet = core::ptr::null_mut();
        let mut host_target = core::ptr::null_mut();
        // SAFETY: Output pointers are valid and successful handles are closed below.
        assert_eq!(
            unsafe {
                NtCreateIoCompletion(
                    &raw mut host_iocp,
                    IO_COMPLETION_ALL_ACCESS,
                    core::ptr::null(),
                    0,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        // SAFETY: Output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateWaitCompletionPacket(
                    &raw mut host_assoc_packet,
                    WAIT_COMPLETION_PACKET_ALL_ACCESS,
                    core::ptr::null(),
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        // SAFETY: Output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateEvent(
                    &raw mut host_target,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    0,
                    0,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut host_already_signaled = 0xaa;
        // SAFETY: All handles are valid and the output byte points to local storage.
        assert_eq!(
            unsafe {
                NtAssociateWaitCompletionPacket(
                    host_assoc_packet,
                    host_iocp,
                    host_target,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                    0,
                    &raw mut host_already_signaled,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut shim_iocp = Handle::default();
        let mut shim_assoc_packet = Handle::default();
        let mut shim_target = Handle::default();
        let mut shim_already_signaled = 0xaa;
        assert_eq!(
            create_io_completion(&task, &mut shim_iocp, IO_COMPLETION_ALL_ACCESS),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_wait_completion_packet(&task, &mut shim_assoc_packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut shim_target, EVENT_ALL_ACCESS, false),
            NtStatus::SUCCESS
        );
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                shim_assoc_packet,
                shim_iocp,
                shim_target,
                Some(mut_ptr(&mut shim_already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        // SAFETY: The host packet handle is valid for the duration of this call.
        let host_cancel_unsignaled = unsafe { NtCancelWaitCompletionPacket(host_assoc_packet, 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_assoc_packet, false).as_raw(),
            host_cancel_unsignaled
        );
        // SAFETY: Handles were returned by NtCreate* calls in this test.
        unsafe {
            close_host(host_target);
            close_host(host_assoc_packet);
            close_host(host_iocp);
        }

        let mut host_iocp = core::ptr::null_mut();
        let mut host_signaled_packet = core::ptr::null_mut();
        let mut host_signaled_event = core::ptr::null_mut();
        // SAFETY: Output pointers are valid and successful handles are closed below.
        assert_eq!(
            unsafe {
                NtCreateIoCompletion(
                    &raw mut host_iocp,
                    IO_COMPLETION_ALL_ACCESS,
                    core::ptr::null(),
                    0,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        // SAFETY: Output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateWaitCompletionPacket(
                    &raw mut host_signaled_packet,
                    WAIT_COMPLETION_PACKET_ALL_ACCESS,
                    core::ptr::null(),
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        // SAFETY: Output pointer is valid and the returned handle is closed below.
        assert_eq!(
            unsafe {
                NtCreateEvent(
                    &raw mut host_signaled_event,
                    EVENT_ALL_ACCESS,
                    core::ptr::null(),
                    0,
                    1,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        host_already_signaled = 0xaa;
        // SAFETY: All handles are valid and the output byte points to local storage.
        assert_eq!(
            unsafe {
                NtAssociateWaitCompletionPacket(
                    host_signaled_packet,
                    host_iocp,
                    host_signaled_event,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    0,
                    0,
                    &raw mut host_already_signaled,
                )
            },
            NtStatus::SUCCESS.as_raw()
        );
        let mut shim_signaled_packet = Handle::default();
        let mut shim_signaled_event = Handle::default();
        shim_already_signaled = 0xaa;
        assert_eq!(
            create_wait_completion_packet(&task, &mut shim_signaled_packet, None),
            NtStatus::SUCCESS
        );
        assert_eq!(
            create_event(&task, &mut shim_signaled_event, EVENT_ALL_ACCESS, true),
            NtStatus::SUCCESS
        );
        assert_eq!(
            associate_wait_completion_packet(
                &task,
                shim_signaled_packet,
                shim_iocp,
                shim_signaled_event,
                Some(mut_ptr(&mut shim_already_signaled)),
            ),
            NtStatus::SUCCESS
        );
        // SAFETY: The host packet handle is valid for the duration of these calls.
        let host_cancel_signaled_pending =
            unsafe { NtCancelWaitCompletionPacket(host_signaled_packet, 0) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_signaled_packet, false).as_raw(),
            host_cancel_signaled_pending
        );
        // SAFETY: The host packet handle is valid for the duration of this call.
        let host_cancel_signaled_remove =
            unsafe { NtCancelWaitCompletionPacket(host_signaled_packet, 1) };
        assert_eq!(
            cancel_wait_completion_packet(&task, shim_signaled_packet, true).as_raw(),
            host_cancel_signaled_remove
        );
        // SAFETY: Handles were returned by NtCreate* calls in this test.
        unsafe {
            close_host(host_signaled_event);
            close_host(host_signaled_packet);
            close_host(host_iocp);
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_create_wait_completion_packet_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateWaitCompletionPacket(
                handle: *mut *mut c_void,
                access: u32,
                attributes: *const ObjectAttributes,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let task = test_task();

        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        let root_without_name = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::from_raw(4),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        for object_attributes in [None, Some(&bad_length), Some(&root_without_name)] {
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The output pointer is valid, optional attributes reference local values for
            // the duration of the call, and successful host handles are closed below.
            let host_status = unsafe {
                NtCreateWaitCompletionPacket(
                    &raw mut host_handle,
                    WAIT_COMPLETION_PACKET_ALL_ACCESS,
                    object_attributes.map_or(core::ptr::null(), core::ptr::from_ref),
                )
            };
            if host_status == NtStatus::SUCCESS.as_raw() && !host_handle.is_null() {
                // SAFETY: The handle was returned by NtCreateWaitCompletionPacket in this test.
                assert_eq!(unsafe { NtClose(host_handle) }, NtStatus::SUCCESS.as_raw());
            }

            let mut shim_handle = Handle::from_raw(usize::MAX);
            let shim_status = create_wait_completion_packet(
                &task,
                &mut shim_handle,
                object_attributes.map(const_ptr),
            );
            assert_eq!(shim_status.as_raw(), host_status);
            if shim_status == NtStatus::SUCCESS {
                assert!(!shim_handle.is_null());
                assert_eq!(task.sys_nt_close(shim_handle), NtStatus::SUCCESS);
            } else {
                assert_eq!(shim_handle, Handle::from_raw(usize::MAX));
            }
        }
    }
}
