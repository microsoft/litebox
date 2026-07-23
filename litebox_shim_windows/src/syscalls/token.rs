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

use crate::nt_types::{AccessMask, Luid};
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

#[repr(C, packed(4))]
#[derive(Immutable, IntoBytes)]
struct TokenUserInformation {
    user: TokenUser,
    sid: Sid,
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

// TODO(token-luid-allocation): Allocate these from sandbox-wide state once multiple token objects
// or token mutation are supported.
const PRIMARY_TOKEN_ID: Luid = Luid {
    low_part: 1,
    high_part: 0,
};

const PRIMARY_TOKEN_MODIFIED_ID: Luid = Luid {
    low_part: 2,
    high_part: 0,
};

const SYSTEM_LUID: Luid = Luid {
    low_part: 0x3e7,
    high_part: 0,
};

const LOCAL_SYSTEM_SID: Sid = Sid {
    revision: 1,
    sub_authority_count: 1,
    identifier_authority: [0, 0, 0, 0, 0, 5],
    sub_authority: [18],
};

pub(crate) struct TokenObject {
    user: Sid,
    statistics: TokenStatistics,
}

impl TokenObject {
    pub(crate) const fn primary() -> Self {
        Self {
            user: LOCAL_SYSTEM_SID,
            statistics: TokenStatistics {
                token_id: PRIMARY_TOKEN_ID,
                authentication_id: SYSTEM_LUID,
                expiration_time: i64::MAX,
                token_type: TOKEN_TYPE_PRIMARY,
                impersonation_level: SECURITY_ANONYMOUS,
                dynamic_charged: 0,
                dynamic_available: 0,
                group_count: 0,
                privilege_count: 0,
                modified_id: PRIMARY_TOKEN_MODIFIED_ID,
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
                Self::write_token_information_value(
                    token_information,
                    token_information_length,
                    return_length,
                    || {
                        let sid_address = token_information
                            .as_usize()
                            .checked_add(size_of::<TokenUser>())
                            .ok_or(NtStatus::ACCESS_VIOLATION)?;
                        Ok(TokenUserInformation {
                            user: TokenUser {
                                user: SidAndAttributes {
                                    sid: sid_address,
                                    attributes: 0,
                                    padding: 0,
                                },
                            },
                            sid: entry.token.user,
                        })
                    },
                )
            }),
            TokenInformationClass::Privileges => Self::write_token_information_value(
                token_information,
                token_information_length,
                return_length,
                || Ok(TokenPrivileges { privilege_count: 0 }),
            ),
            TokenInformationClass::Statistics => entry.with_entry(|entry| {
                Self::write_token_information_value(
                    token_information,
                    token_information_length,
                    return_length,
                    || Ok(entry.token.statistics),
                )
            }),
            _ => {
                // TODO(token-model): Add each information class when its backing token state is
                // modeled; do not synthesize security-sensitive token data.
                NtStatus::NOT_IMPLEMENTED
            }
        }
    }

    fn write_token_information_value<T: Immutable + IntoBytes>(
        token_information: MutPtr<Platform, u8>,
        token_information_length: u32,
        return_length: MutPtr<Platform, u32>,
        build_information: impl FnOnce() -> Result<T, NtStatus>,
    ) -> NtStatus {
        let required_length = size_of::<T>().trunc();
        if return_length.write_at_offset(0, required_length).is_none() {
            return NtStatus::ACCESS_VIOLATION;
        }
        if token_information_length < required_length {
            return NtStatus::BUFFER_TOO_SMALL;
        }
        let information = match build_information() {
            Ok(information) => information,
            Err(status) => return status,
        };
        if token_information
            .write_slice_at_offset(0, information.as_bytes())
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
        assert_eq!(
            required_length as usize,
            size_of::<TokenUser>() + size_of::<Sid>()
        );

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
}
