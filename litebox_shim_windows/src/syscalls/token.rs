// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows NT access-token syscalls.

use alloc::sync::Arc;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry};
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox::utils::TruncateExt as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::AccessMask;
use crate::syscalls::{Handle, ProcessHandle};
use crate::{
    HandleAttributes, MutPtr, ShimFS, Task, WindowsHandleSubsystem, probe_guest_output_buffer,
    probe_guest_output_preserving_value,
};

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct TokenAccess: u32 {
        const ASSIGN_PRIMARY = 0x0001;
        const DUPLICATE = 0x0002;
        const IMPERSONATE = 0x0004;
        const QUERY = 0x0008;
        const QUERY_SOURCE = 0x0010;
        const ADJUST_PRIVILEGES = 0x0020;
        const ADJUST_GROUPS = 0x0040;
        const ADJUST_DEFAULT = 0x0080;
        const ADJUST_SESSION_ID = 0x0100;

        const READ = AccessMask::STANDARD_RIGHTS_READ.bits() | Self::QUERY.bits();
        const WRITE = AccessMask::STANDARD_RIGHTS_WRITE.bits()
            | Self::ADJUST_PRIVILEGES.bits()
            | Self::ADJUST_GROUPS.bits()
            | Self::ADJUST_DEFAULT.bits();
        const EXECUTE = AccessMask::STANDARD_RIGHTS_EXECUTE.bits();
        const ALL_ACCESS = AccessMask::DELETE.bits()
            | AccessMask::READ_CONTROL.bits()
            | AccessMask::WRITE_DAC.bits()
            | AccessMask::WRITE_OWNER.bits()
            | Self::ASSIGN_PRIMARY.bits()
            | Self::DUPLICATE.bits()
            | Self::IMPERSONATE.bits()
            | Self::QUERY.bits()
            | Self::QUERY_SOURCE.bits()
            | Self::ADJUST_PRIVILEGES.bits()
            | Self::ADJUST_GROUPS.bits()
            | Self::ADJUST_DEFAULT.bits()
            | Self::ADJUST_SESSION_ID.bits();

        const _ = !0;
    }
}

impl TokenAccess {
    fn from_desired_access(desired_access: u32) -> Self {
        let maximum_allowed = desired_access & AccessMask::MAXIMUM_ALLOWED.bits() != 0;
        let explicit_access = desired_access & !AccessMask::MAXIMUM_ALLOWED.bits();
        let normalized = AccessMask::expand_generic_access(
            explicit_access,
            Self::READ.bits(),
            Self::WRITE.bits(),
            Self::EXECUTE.bits(),
            Self::ALL_ACCESS.bits(),
        );
        Self::from_bits_retain(if maximum_allowed {
            normalized | Self::ALL_ACCESS.bits()
        } else {
            normalized
        })
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
pub(crate) enum TokenInformationClass {
    User = 1,
    Groups = 2,
    Privileges = 3,
    Owner = 4,
    PrimaryGroup = 5,
    DefaultDacl = 6,
    Source = 7,
    Type = 8,
    ImpersonationLevel = 9,
    Statistics = 10,
    RestrictedSids = 11,
    SessionId = 12,
    GroupsAndPrivileges = 13,
    SessionReference = 14,
    SandBoxInert = 15,
    AuditPolicy = 16,
    Origin = 17,
    ElevationType = 18,
    LinkedToken = 19,
    Elevation = 20,
    HasRestrictions = 21,
    AccessInformation = 22,
    VirtualizationAllowed = 23,
    VirtualizationEnabled = 24,
    IntegrityLevel = 25,
    UiAccess = 26,
    MandatoryPolicy = 27,
    LogonSid = 28,
    IsAppContainer = 29,
    Capabilities = 30,
    AppContainerSid = 31,
    AppContainerNumber = 32,
    UserClaimAttributes = 33,
    DeviceClaimAttributes = 34,
    RestrictedUserClaimAttributes = 35,
    RestrictedDeviceClaimAttributes = 36,
    DeviceGroups = 37,
    RestrictedDeviceGroups = 38,
    SecurityAttributes = 39,
    IsRestricted = 40,
    ProcessTrustLevel = 41,
    PrivateNameSpace = 42,
    SingletonAttributes = 43,
    BnoIsolation = 44,
    ChildProcessFlags = 45,
    IsLessPrivilegedAppContainer = 46,
    IsSandboxed = 47,
    IsAppSilo = 48,
    LoggingInformation = 49,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct Luid {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct SidAndAttributes {
    sid: usize,
    attributes: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct TokenUser {
    user: SidAndAttributes,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct Sid {
    revision: u8,
    sub_authority_count: u8,
    identifier_authority: [u8; 6],
    sub_authority: [u32; 1],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct TokenPrivileges {
    privilege_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
pub(crate) struct TokenStatistics {
    token_id: Luid,
    authentication_id: Luid,
    expiration_time: i64,
    token_type: u32,
    impersonation_level: u32,
    dynamic_charged: u32,
    dynamic_available: u32,
    group_count: u32,
    privilege_count: u32,
    modified_id: Luid,
}

const TOKEN_TYPE_PRIMARY: u32 = 1;
const SECURITY_ANONYMOUS: u32 = 0;

const LOCAL_SYSTEM_SID: Sid = Sid {
    revision: 1,
    sub_authority_count: 1,
    identifier_authority: [0, 0, 0, 0, 0, 5],
    sub_authority: [18],
};

const TOKEN_USER_SIZE: usize = size_of::<TokenUser>() + size_of::<Sid>();
const TOKEN_USER_SID_OFFSET: isize = 16;
const TOKEN_PRIVILEGES_SIZE: usize = size_of::<TokenPrivileges>();
const TOKEN_STATISTICS_SIZE: usize = size_of::<TokenStatistics>();

const _: () = assert!(size_of::<TokenUser>() == 16);
const _: () = assert!(size_of::<Sid>() == 12);
const _: () = assert!(TOKEN_USER_SIZE == 28);
const _: () = assert!(TOKEN_PRIVILEGES_SIZE == 4);
const _: () = assert!(TOKEN_STATISTICS_SIZE == 56);

pub(crate) struct TokenObject {
    user: Sid,
    statistics: TokenStatistics,
}

impl TokenObject {
    pub(crate) const fn primary() -> Self {
        Self {
            user: LOCAL_SYSTEM_SID,
            statistics: TokenStatistics {
                token_id: Luid {
                    low_part: 1,
                    high_part: 0,
                },
                authentication_id: Luid {
                    low_part: 0x3e7,
                    high_part: 0,
                },
                expiration_time: i64::MAX,
                token_type: TOKEN_TYPE_PRIMARY,
                impersonation_level: SECURITY_ANONYMOUS,
                dynamic_charged: 0,
                dynamic_available: 0,
                group_count: 0,
                privilege_count: 0,
                modified_id: Luid {
                    low_part: 2,
                    high_part: 0,
                },
            },
        }
    }
}

pub(crate) struct TokenHandleObject {
    token: Arc<TokenObject>,
}

pub(crate) struct TokenSubsystem;

impl FdEnabledSubsystem for TokenSubsystem {
    type Entry = TokenHandleObject;
}

impl FdEnabledSubsystemEntry for TokenHandleObject {}

impl WindowsHandleSubsystem for TokenSubsystem {
    fn normalize_desired_access(desired_access: u32) -> u32 {
        TokenAccess::from_desired_access(desired_access).bits()
    }
}

impl<Platform: crate::ShimPlatform, FS: ShimFS> Task<Platform, FS> {
    pub(crate) fn sys_nt_open_process_token(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        self.open_process_token(process_handle, desired_access, 0, token_handle)
    }

    pub(crate) fn sys_nt_open_process_token_ex(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        handle_attributes: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        self.open_process_token(
            process_handle,
            desired_access,
            handle_attributes,
            token_handle,
        )
    }

    fn open_process_token(
        &self,
        process_handle: ProcessHandle,
        desired_access: u32,
        handle_attributes: u32,
        token_handle: MutPtr<Platform, Handle>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(token_handle) {
            return status;
        }
        let Some(attributes) = HandleAttributes::from_token_open_attributes(handle_attributes)
        else {
            return NtStatus::INVALID_PARAMETER;
        };
        if !process_handle.is_current() {
            // TODO(token-cross-process): Resolve real process handles once the sandbox supports
            // multiple guest processes and per-process primary tokens.
            return NtStatus::INVALID_HANDLE;
        }

        let handle = match self.insert_typed_handle_with_attributes::<TokenSubsystem>(
            TokenHandleObject {
                token: self.process.token.clone(),
            },
            TokenAccess::from_desired_access(desired_access).bits(),
            attributes,
            drop,
        ) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        if token_handle.write_at_offset(0, handle).is_none() {
            self.close_token_handle(handle);
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn sys_nt_query_information_token(
        &self,
        token_handle: Handle,
        token_information_class: u32,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        if let Err(status) = probe_guest_output_preserving_value::<Platform, _>(return_length) {
            return status;
        }
        let Ok(class) = TokenInformationClass::try_from(token_information_class) else {
            return NtStatus::INVALID_INFO_CLASS;
        };
        if let Err(status) = probe_guest_output_buffer::<Platform>(
            token_information,
            token_information_length as usize,
        ) {
            return status;
        }

        let entry = match self.typed_handle_entry_with_access::<TokenSubsystem>(
            token_handle,
            TokenAccess::QUERY.bits(),
        ) {
            Ok(entry) => entry,
            Err(status) => return status,
        };

        match class {
            TokenInformationClass::User => entry.with_entry(|entry| {
                Self::write_token_user(
                    &entry.token,
                    token_information,
                    token_information_length,
                    return_length,
                )
            }),
            TokenInformationClass::Privileges => entry.with_entry(|entry| {
                Self::write_token_privileges(
                    &entry.token,
                    token_information,
                    token_information_length,
                    return_length,
                )
            }),
            TokenInformationClass::Statistics => entry.with_entry(|entry| {
                Self::write_token_statistics(
                    &entry.token,
                    token_information,
                    token_information_length,
                    return_length,
                )
            }),
            _ => {
                // TODO(token-model): Add each information class when its backing token state is
                // modeled; do not synthesize security-sensitive token data.
                NtStatus::NOT_IMPLEMENTED
            }
        }
    }

    fn write_token_user(
        token: &TokenObject,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let required_length = TOKEN_USER_SIZE.trunc();
        if return_length.write_at_offset(0, required_length).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if token_information_length < required_length {
            return NtStatus::BUFFER_TOO_SMALL;
        }

        let Some(sid_address) = token_information
            .as_usize()
            .checked_add(size_of::<TokenUser>())
        else {
            return NtStatus::ACCESS_VIOLATION;
        };
        let user = TokenUser {
            user: SidAndAttributes {
                sid: sid_address,
                attributes: 0,
                padding: 0,
            },
        };
        if token_information
            .write_slice_at_offset(0, user.as_bytes())
            .is_none()
            || token_information
                .write_slice_at_offset(TOKEN_USER_SID_OFFSET, token.user.as_bytes())
                .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_token_privileges(
        _token: &TokenObject,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let required_length = TOKEN_PRIVILEGES_SIZE.trunc();
        if return_length.write_at_offset(0, required_length).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if token_information_length < required_length {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        let privileges = TokenPrivileges { privilege_count: 0 };
        if token_information
            .write_slice_at_offset(0, privileges.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    fn write_token_statistics(
        token: &TokenObject,
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
    ) -> NtStatus {
        let required_length = TOKEN_STATISTICS_SIZE.trunc();
        if return_length.write_at_offset(0, required_length).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if token_information_length < required_length {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        if token_information
            .write_slice_at_offset(0, token.statistics.as_bytes())
            .is_none()
        {
            return NtStatus::ACCESS_VIOLATION;
        }
        NtStatus::SUCCESS
    }

    pub(crate) fn close_token_handle(&self, handle: Handle) {
        self.close_typed_handle::<TokenSubsystem>(handle, drop);
    }

    pub(crate) fn close_token(token: TokenHandleObject) {
        drop(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{mut_byte_ptr, mut_ptr, null_mut_ptr, test_task};
    use crate::{DuplicateOptions, tests::TestPlatform};
    use litebox::platform::ThreadProvider;

    #[repr(C)]
    #[derive(Clone, Copy, Debug, Eq, FromBytes, Immutable, IntoBytes, PartialEq)]
    struct TokenUserBuffer {
        user: TokenUser,
        sid: Sid,
        padding: u32,
    }

    #[test]
    fn open_and_query_process_token_identity() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_process_token(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                mut_ptr(&mut handle),
            ),
            NtStatus::SUCCESS
        );

        let mut required_length = 0;
        assert_eq!(
            task.sys_nt_query_information_token(
                handle,
                TokenInformationClass::User as u32,
                null_mut_ptr(),
                0,
                mut_ptr(&mut required_length),
            ),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(required_length as usize, TOKEN_USER_SIZE);

        let mut output = TokenUserBuffer {
            user: TokenUser {
                user: SidAndAttributes {
                    sid: 0,
                    attributes: u32::MAX,
                    padding: 0,
                },
            },
            sid: Sid {
                revision: 0,
                sub_authority_count: 0,
                identifier_authority: [0; 6],
                sub_authority: [0],
            },
            padding: 0,
        };
        assert_eq!(
            task.sys_nt_query_information_token(
                handle,
                TokenInformationClass::User as u32,
                mut_byte_ptr(&mut output),
                required_length,
                mut_ptr(&mut required_length),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            output.user.user.sid,
            core::ptr::from_ref(&output.sid) as usize
        );
        assert_eq!(output.user.user.attributes, 0);
        assert_eq!(output.sid, LOCAL_SYSTEM_SID);
    }

    #[test]
    fn query_process_token_reports_privileges_and_statistics() {
        let task = test_task();
        let mut handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_process_token_ex(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                HandleAttributes::INHERIT.bits(),
                mut_ptr(&mut handle),
            ),
            NtStatus::SUCCESS
        );

        let mut privileges = TokenPrivileges {
            privilege_count: u32::MAX,
        };
        let mut return_length = 0;
        assert_eq!(
            task.sys_nt_query_information_token(
                handle,
                TokenInformationClass::Privileges as u32,
                mut_byte_ptr(&mut privileges),
                size_of::<TokenPrivileges>().trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length as usize, TOKEN_PRIVILEGES_SIZE);
        assert_eq!(privileges.privilege_count, 0);

        let mut statistics = TokenStatistics {
            token_id: Luid {
                low_part: 0,
                high_part: 0,
            },
            authentication_id: Luid {
                low_part: 0,
                high_part: 0,
            },
            expiration_time: 0,
            token_type: 0,
            impersonation_level: 0,
            dynamic_charged: 0,
            dynamic_available: 0,
            group_count: u32::MAX,
            privilege_count: u32::MAX,
            modified_id: Luid {
                low_part: 0,
                high_part: 0,
            },
        };
        assert_eq!(
            task.sys_nt_query_information_token(
                handle,
                TokenInformationClass::Statistics as u32,
                mut_byte_ptr(&mut statistics),
                size_of::<TokenStatistics>().trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(return_length as usize, TOKEN_STATISTICS_SIZE);
        assert_eq!(statistics.authentication_id.low_part, 0x3e7);
        assert_eq!(statistics.token_type, TOKEN_TYPE_PRIMARY);
        assert_eq!(statistics.group_count, 0);
        assert_eq!(statistics.privilege_count, 0);
    }

    #[test]
    fn query_process_token_enforces_buffer_and_access() {
        let task = test_task();
        let mut query_handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_process_token(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                mut_ptr(&mut query_handle),
            ),
            NtStatus::SUCCESS
        );

        let mut output = [0xa5_u8; TOKEN_STATISTICS_SIZE];
        let mut return_length = 0;
        assert_eq!(
            task.sys_nt_query_information_token(
                query_handle,
                TokenInformationClass::Statistics as u32,
                mut_byte_ptr(&mut output),
                (TOKEN_STATISTICS_SIZE - 1).trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::BUFFER_TOO_SMALL
        );
        assert_eq!(return_length as usize, TOKEN_STATISTICS_SIZE);
        assert_eq!(output, [0xa5; TOKEN_STATISTICS_SIZE]);

        let mut duplicate_only_handle = Handle::default();
        assert_eq!(
            task.sys_nt_open_process_token(
                ProcessHandle::CURRENT,
                TokenAccess::DUPLICATE.bits(),
                mut_ptr(&mut duplicate_only_handle),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(
            task.sys_nt_query_information_token(
                duplicate_only_handle,
                TokenInformationClass::Statistics as u32,
                mut_byte_ptr(&mut output),
                TOKEN_STATISTICS_SIZE.trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::ACCESS_DENIED
        );
    }

    #[test]
    fn open_process_token_validates_process_and_attributes() {
        let task = test_task();
        let sentinel = Handle::from_raw(0x1122_3344);
        let mut handle = sentinel;
        assert_eq!(
            task.sys_nt_open_process_token(
                ProcessHandle::from_raw(0x1234),
                TokenAccess::QUERY.bits(),
                mut_ptr(&mut handle),
            ),
            NtStatus::INVALID_HANDLE
        );
        assert_eq!(handle, sentinel);

        assert_eq!(
            task.sys_nt_open_process_token_ex(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                0x20,
                mut_ptr(&mut handle),
            ),
            NtStatus::INVALID_PARAMETER
        );
        assert_eq!(handle, sentinel);

        assert_eq!(
            task.sys_nt_open_process_token_ex(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                0x40,
                mut_ptr(&mut handle),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.sys_nt_close(handle), NtStatus::SUCCESS);
    }

    #[test]
    fn duplicated_token_handle_remains_queryable_after_source_close() {
        let task = test_task();
        let mut source = Handle::default();
        assert_eq!(
            task.sys_nt_open_process_token(
                ProcessHandle::CURRENT,
                TokenAccess::QUERY.bits(),
                mut_ptr(&mut source),
            ),
            NtStatus::SUCCESS
        );
        let mut duplicate = Handle::default();
        assert_eq!(
            task.sys_nt_duplicate_object(
                ProcessHandle::CURRENT,
                source,
                ProcessHandle::CURRENT,
                Some(mut_ptr(&mut duplicate)),
                0,
                0,
                DuplicateOptions::SAME_ACCESS.bits(),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(task.sys_nt_close(source), NtStatus::SUCCESS);

        let mut privileges = TokenPrivileges {
            privilege_count: u32::MAX,
        };
        let mut return_length = 0;
        assert_eq!(
            task.sys_nt_query_information_token(
                duplicate,
                TokenInformationClass::Privileges as u32,
                mut_byte_ptr(&mut privileges),
                TOKEN_PRIVILEGES_SIZE.trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::SUCCESS
        );
        assert_eq!(privileges.privilege_count, 0);
        assert_eq!(task.sys_nt_close(duplicate), NtStatus::SUCCESS);
        assert_eq!(
            task.sys_nt_query_information_token(
                duplicate,
                TokenInformationClass::Privileges as u32,
                mut_byte_ptr(&mut privileges),
                TOKEN_PRIVILEGES_SIZE.trunc(),
                mut_ptr(&mut return_length),
            ),
            NtStatus::INVALID_HANDLE
        );
    }

    #[test]
    fn query_process_token_requires_return_length() {
        let _ = crate::tests::test_platform();
        <TestPlatform as ThreadProvider>::run_test_thread(|| {
            let task = test_task();
            let mut handle = Handle::default();
            assert_eq!(
                task.sys_nt_open_process_token(
                    ProcessHandle::CURRENT,
                    TokenAccess::QUERY.bits(),
                    mut_ptr(&mut handle),
                ),
                NtStatus::SUCCESS
            );
            assert_eq!(
                task.sys_nt_query_information_token(
                    handle,
                    TokenInformationClass::User as u32,
                    null_mut_ptr(),
                    0,
                    MutPtr::<TestPlatform, u32>::from_usize(0),
                ),
                NtStatus::ACCESS_VIOLATION
            );
        });
    }
}
