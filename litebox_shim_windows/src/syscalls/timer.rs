// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT timer syscalls.

use alloc::sync::Arc;
use core::marker::PhantomData;

use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;

use crate::nt_types::{AccessMask, ObjectAttributes};
use crate::syscalls::Handle;
use crate::{ConstPtr, MutPtr, ShimFS, Task, probe_guest_output_preserving_value};

const TIMER2_ATTRIBUTE_IR_TIMER: u32 = 0x0000_0002;
const TIMER2_ATTRIBUTE_HIGH_RESOLUTION: u32 = 0x0000_0004;
const TIMER2_ATTRIBUTE_NO_WAKE: u32 = 0x0000_0008;
const TIMER2_ATTRIBUTE_NOTIFICATION: u32 = 0x8000_0000;
const TIMER2_ATTRIBUTE_KNOWN_MASK: u32 = TIMER2_ATTRIBUTE_IR_TIMER
    | TIMER2_ATTRIBUTE_HIGH_RESOLUTION
    | TIMER2_ATTRIBUTE_NO_WAKE
    | TIMER2_ATTRIBUTE_NOTIFICATION;
const TIMER2_ATTRIBUTE_RESERVED_MASK: u32 = !TIMER2_ATTRIBUTE_KNOWN_MASK;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct TimerAccess: u32 {
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

impl TimerAccess {
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

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct Timer2Attributes: u32 {
        const HIGH_RESOLUTION = TIMER2_ATTRIBUTE_HIGH_RESOLUTION;
        const NO_WAKE = TIMER2_ATTRIBUTE_NO_WAKE;
        const NOTIFICATION = TIMER2_ATTRIBUTE_NOTIFICATION;

        const _ = !0;
    }
}

pub(crate) struct TimerSubsystem<Platform>(PhantomData<fn(Platform)>);

impl<Platform: crate::ShimPlatform> FdEnabledSubsystem for TimerSubsystem<Platform> {
    type Entry = TimerHandleObject<Platform>;
}

impl<Platform: crate::ShimPlatform> FdEnabledSubsystemEntry for TimerHandleObject<Platform> {}

impl<Platform: crate::ShimPlatform> crate::WindowsHandleSubsystem for TimerSubsystem<Platform> {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        TimerAccess::from_desired_access(desired_access).bits()
    }
}

pub(crate) struct TimerHandleObject<Platform: crate::ShimPlatform> {
    _timer: Arc<TimerObject<Platform>>,
}

pub(crate) struct TimerObject<Platform: crate::ShimPlatform> {
    _attributes: Timer2Attributes,
    _not_send_without_platform: PhantomData<fn(Platform)>,
}

pub(crate) struct TimerCreateParameters<Platform: RawPointerProvider> {
    pub(crate) timer_handle: MutPtr<Platform, Handle>,
    pub(crate) timer_id: Option<ConstPtr<Platform, u32>>,
    pub(crate) object_attributes: Option<ConstPtr<Platform, ObjectAttributes>>,
    pub(crate) attributes: u32,
    pub(crate) desired_access: u32,
}

fn validate_timer2_before_output<Platform: RawPointerProvider>(
    params: &TimerCreateParameters<Platform>,
) -> Result<(), NtStatus> {
    if params.object_attributes.is_some() {
        return Err(NtStatus::INVALID_PARAMETER_3);
    }
    if params.attributes & TIMER2_ATTRIBUTE_RESERVED_MASK != 0 {
        return Err(NtStatus::INVALID_PARAMETER_4);
    }
    if params.attributes & TIMER2_ATTRIBUTE_IR_TIMER == 0 && params.timer_id.is_some() {
        return Err(NtStatus::INVALID_PARAMETER_2);
    }
    Ok(())
}

fn validate_timer2_after_output<Platform: RawPointerProvider>(
    params: &TimerCreateParameters<Platform>,
) -> Result<(), NtStatus> {
    if params.attributes & TIMER2_ATTRIBUTE_IR_TIMER == 0 {
        return Ok(());
    }
    if params.timer_id.is_some() {
        Err(NtStatus::ACCESS_DENIED)
    } else {
        Err(NtStatus::INVALID_PARAMETER)
    }
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    fn insert_timer_handle(
        &self,
        timer: Arc<TimerObject<Platform>>,
        granted_access: TimerAccess,
    ) -> Result<Handle, NtStatus> {
        self.insert_typed_handle::<TimerSubsystem<Platform>>(
            TimerHandleObject { _timer: timer },
            granted_access.bits(),
            drop,
        )
    }

    pub(crate) fn close_timer_handle(&self, handle: Handle) {
        self.close_typed_handle::<TimerSubsystem<Platform>>(handle, drop);
    }

    pub(crate) fn close_timer(timer: TimerHandleObject<Platform>) {
        drop(timer);
    }

    pub(crate) fn sys_nt_create_timer2(&self, params: TimerCreateParameters<Platform>) -> NtStatus {
        if let Err(status) = validate_timer2_before_output(&params) {
            return status;
        }
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(params.timer_handle)
        {
            return status;
        }
        if let Err(status) = validate_timer2_after_output(&params) {
            return status;
        }

        let timer = Arc::new(TimerObject {
            // TODO: store timer state once NtSetTimer2 schedules due times and waiters can
            // observe expiration/signaling instead of only validating the handle shape.
            _attributes: Timer2Attributes::from_bits_retain(params.attributes),
            _not_send_without_platform: PhantomData,
        });
        let granted_access = TimerAccess::from_desired_access(params.desired_access);
        let Ok(handle) = self.insert_timer_handle(timer, granted_access) else {
            return NtStatus::QUOTA_EXCEEDED;
        };
        if params.timer_handle.write_at_offset(0, handle).is_none() {
            self.close_timer_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_set_timer2(
        &self,
        timer_handle: Handle,
        due_time: Option<ConstPtr<Platform, i64>>,
        period: Option<ConstPtr<Platform, i64>>,
        parameters: Option<ConstPtr<Platform, u8>>,
    ) -> NtStatus {
        if let Err(status) = self.require_handle_access::<TimerSubsystem<Platform>>(
            timer_handle,
            TimerAccess::MODIFY_STATE.bits(),
        ) {
            return status;
        }
        let _due_time = match due_time {
            Some(due_time) => match due_time.read_at_offset(0) {
                Some(due_time) => Some(due_time),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };
        let _period = match period {
            Some(period) => match period.read_at_offset(0) {
                Some(period) => Some(period),
                None => return NtStatus::ACCESS_VIOLATION,
            },
            None => None,
        };

        // TODO: parse T2_SET_PARAMETERS and model callbacks/tolerable delay when the timer
        // object grows real scheduling and notification behavior.
        let _ = parameters;

        // TODO: store due_time/period, transition the timer's signaled state, and notify
        // waiters or associated wait-completion packets instead of returning a no-op success.
        NtStatus::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use litebox::platform::ThreadProvider;
    use litebox_common_windows::nt_status::NtStatus;

    use super::*;
    use crate::nt_types::ObjectAttributes;
    use crate::tests::{TestPlatform, const_ptr, mut_ptr, null_mut_ptr, test_platform, test_task};

    const TIMER_ALL_ACCESS: u32 = 0x001f_0003;

    fn object_attributes_size() -> u32 {
        u32::try_from(size_of::<ObjectAttributes>()).expect("OBJECT_ATTRIBUTES fits in ULONG")
    }

    fn run_with_test_platform_pointers<R>(f: impl FnOnce() -> R) -> R {
        let _ = test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(f)
    }

    fn create_timer2(
        task: &Task<TestPlatform, crate::tests::TestFS>,
        handle: &mut Handle,
        timer_id: Option<ConstPtr<TestPlatform, u32>>,
        object_attributes: Option<ConstPtr<TestPlatform, ObjectAttributes>>,
        attributes: u32,
    ) -> NtStatus {
        task.sys_nt_create_timer2(TimerCreateParameters {
            timer_handle: mut_ptr(handle),
            timer_id,
            object_attributes,
            attributes,
            desired_access: TIMER_ALL_ACCESS,
        })
    }

    #[test]
    fn set_timer2_accepts_created_timer() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let mut handle = Handle::default();
            let due_time = -10_000i64;
            let period = 0i64;

            assert_eq!(
                create_timer2(&task, &mut handle, None, None, 0),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_set_timer2(
                    handle,
                    Some(const_ptr(&due_time)),
                    Some(const_ptr(&period)),
                    None
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
        });
    }

    #[test]
    fn create_rejects_object_attributes_before_output_pointer() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let bad_length = ObjectAttributes {
                length: 1,
                root_directory: Handle::default(),
                object_name: 0,
                attributes: 0,
                security_descriptor: 0,
                security_quality_of_service: 0,
            };

            assert_eq!(
                task.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle: null_mut_ptr(),
                    timer_id: None,
                    object_attributes: Some(const_ptr(&bad_length)),
                    attributes: 0,
                    desired_access: TIMER_ALL_ACCESS,
                }),
                NtStatus::INVALID_PARAMETER_3
            );
        });
    }

    #[test]
    fn create_validates_reserved_bits_and_non_ir_timer_id_before_output_pointer() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let timer_id = 1u32;

            assert_eq!(
                task.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle: null_mut_ptr(),
                    timer_id: None,
                    object_attributes: None,
                    attributes: 1,
                    desired_access: TIMER_ALL_ACCESS,
                }),
                NtStatus::INVALID_PARAMETER_4
            );
            assert_eq!(
                task.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle: null_mut_ptr(),
                    timer_id: Some(const_ptr(&timer_id)),
                    object_attributes: None,
                    attributes: TIMER2_ATTRIBUTE_NOTIFICATION,
                    desired_access: TIMER_ALL_ACCESS,
                }),
                NtStatus::INVALID_PARAMETER_2
            );
        });
    }

    #[test]
    fn create_probes_output_pointer_before_ir_timer_validation() {
        run_with_test_platform_pointers(|| {
            let task = test_task();
            let timer_id = 1u32;

            assert_eq!(
                task.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle: null_mut_ptr(),
                    timer_id: None,
                    object_attributes: None,
                    attributes: TIMER2_ATTRIBUTE_IR_TIMER,
                    desired_access: TIMER_ALL_ACCESS,
                }),
                NtStatus::ACCESS_VIOLATION
            );
            assert_eq!(
                task.sys_nt_create_timer2(TimerCreateParameters {
                    timer_handle: null_mut_ptr(),
                    timer_id: Some(const_ptr(&timer_id)),
                    object_attributes: None,
                    attributes: TIMER2_ATTRIBUTE_IR_TIMER,
                    desired_access: TIMER_ALL_ACCESS,
                }),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }

    #[test]
    fn create_rejects_ir_timers_without_clobbering_output() {
        let task = test_task();
        let timer_id = 1u32;
        let mut handle = Handle::from_raw(usize::MAX);

        assert_eq!(
            create_timer2(&task, &mut handle, None, None, TIMER2_ATTRIBUTE_IR_TIMER),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
        assert_eq!(
            create_timer2(
                &task,
                &mut handle,
                Some(const_ptr(&timer_id)),
                None,
                TIMER2_ATTRIBUTE_IR_TIMER
            ),
            NtStatus::ACCESS_DENIED
        );
        assert_eq!(handle, Handle::from_raw(usize::MAX));
    }

    #[test]
    fn create_rejections_do_not_clobber_output() {
        let task = test_task();
        let timer_id = 1u32;
        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };
        let valid_length = ObjectAttributes {
            length: object_attributes_size(),
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        for (timer_id, object_attributes, attributes, expected_status) in [
            (
                None,
                Some(const_ptr(&bad_length)),
                0,
                NtStatus::INVALID_PARAMETER_3,
            ),
            (
                None,
                Some(const_ptr(&valid_length)),
                0,
                NtStatus::INVALID_PARAMETER_3,
            ),
            (None, None, 1, NtStatus::INVALID_PARAMETER_4),
            (
                Some(const_ptr(&timer_id)),
                None,
                TIMER2_ATTRIBUTE_HIGH_RESOLUTION,
                NtStatus::INVALID_PARAMETER_2,
            ),
        ] {
            let mut handle = Handle::from_raw(usize::MAX);
            assert_eq!(
                create_timer2(&task, &mut handle, timer_id, object_attributes, attributes),
                expected_status
            );
            assert_eq!(handle, Handle::from_raw(usize::MAX));
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    #[test]
    fn host_create_timer2_status_fidelity() {
        use core::ffi::c_void;

        unsafe extern "system" {
            fn NtCreateTimer2(
                handle: *mut *mut c_void,
                timer_id: *const u32,
                object_attributes: *const ObjectAttributes,
                attributes: u32,
                desired_access: u32,
            ) -> i32;
            fn NtClose(handle: *mut c_void) -> i32;
        }

        let task = test_task();
        let timer_id = 1u32;
        let bad_length = ObjectAttributes {
            length: 1,
            root_directory: Handle::default(),
            object_name: 0,
            attributes: 0,
            security_descriptor: 0,
            security_quality_of_service: 0,
        };

        for (timer_id, object_attributes, attributes) in [
            (None, None, 0),
            (None, None, TIMER2_ATTRIBUTE_HIGH_RESOLUTION),
            (None, None, TIMER2_ATTRIBUTE_NO_WAKE),
            (
                None,
                None,
                TIMER2_ATTRIBUTE_HIGH_RESOLUTION | TIMER2_ATTRIBUTE_NO_WAKE,
            ),
            (None, None, TIMER2_ATTRIBUTE_NOTIFICATION),
            (
                None,
                None,
                TIMER2_ATTRIBUTE_NOTIFICATION
                    | TIMER2_ATTRIBUTE_HIGH_RESOLUTION
                    | TIMER2_ATTRIBUTE_NO_WAKE,
            ),
            (None, None, 1),
            (Some(&timer_id), None, TIMER2_ATTRIBUTE_HIGH_RESOLUTION),
            (None, Some(&bad_length), 0),
            (None, None, TIMER2_ATTRIBUTE_IR_TIMER),
            (Some(&timer_id), None, TIMER2_ATTRIBUTE_IR_TIMER),
        ] {
            let mut host_handle = core::ptr::null_mut();
            // SAFETY: The output pointer is valid, optional input pointers reference local values
            // for the duration of the call, and successful host handles are closed below.
            let host_status = unsafe {
                NtCreateTimer2(
                    &raw mut host_handle,
                    timer_id.map_or(core::ptr::null(), core::ptr::from_ref),
                    object_attributes.map_or(core::ptr::null(), core::ptr::from_ref),
                    attributes,
                    TIMER_ALL_ACCESS,
                )
            };
            if host_status == NtStatus::SUCCESS.as_raw() && !host_handle.is_null() {
                // SAFETY: The handle was returned by NtCreateTimer2 in this test.
                assert_eq!(unsafe { NtClose(host_handle) }, NtStatus::SUCCESS.as_raw());
            }

            let mut shim_handle = Handle::default();
            let shim_status = create_timer2(
                &task,
                &mut shim_handle,
                timer_id.map(const_ptr),
                object_attributes.map(const_ptr),
                attributes,
            );
            assert_eq!(shim_status.as_raw(), host_status);
            if shim_status == NtStatus::SUCCESS {
                assert!(!shim_handle.is_null());
                assert_eq!(task.sys_nt_close(shim_handle), NtStatus::SUCCESS);
            }
        }
    }
}
