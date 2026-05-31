// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use litebox::platform::{RawConstPointer as _, RawPointerProvider};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::{ConstPtr, syscalls::Handle};

bitflags::bitflags! {
    /// Common Windows object-manager `ACCESS_MASK` rights shared by NT object types.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) struct AccessMask: u32 {
        const DELETE = 0x0001_0000;
        const READ_CONTROL = 0x0002_0000;
        const WRITE_DAC = 0x0004_0000;
        const WRITE_OWNER = 0x0008_0000;
        const SYNCHRONIZE = 0x0010_0000;
        const STANDARD_RIGHTS_READ = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_WRITE = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_EXECUTE = Self::READ_CONTROL.bits();
        const STANDARD_RIGHTS_ALL = Self::DELETE.bits()
            | Self::READ_CONTROL.bits()
            | Self::WRITE_DAC.bits()
            | Self::WRITE_OWNER.bits()
            | Self::SYNCHRONIZE.bits();

        const GENERIC_ALL = 0x1000_0000;
        const GENERIC_EXECUTE = 0x2000_0000;
        const GENERIC_WRITE = 0x4000_0000;
        const GENERIC_READ = 0x8000_0000;

        const _ = !0;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct ObjectAttributes {
    pub(crate) length: u32,
    pub(crate) root_directory: Handle,
    pub(crate) object_name: usize,
    pub(crate) attributes: u32,
    pub(crate) security_descriptor: usize,
    pub(crate) security_quality_of_service: usize,
}

pub(crate) fn read_object_attributes<Platform: RawPointerProvider>(
    object_attributes: ConstPtr<Platform, ObjectAttributes>,
) -> Result<ObjectAttributes, NtStatus> {
    let Some(object_attributes) = object_attributes.read_at_offset(0) else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    if object_attributes.length as usize != size_of::<ObjectAttributes>() {
        return Err(NtStatus::INVALID_PARAMETER);
    }
    Ok(object_attributes)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable)]
pub(crate) struct UnicodeString {
    pub(crate) length: u16,
    pub(crate) maximum_length: u16,
    pub(crate) padding_0: [u8; 4],
    pub(crate) buffer: usize,
}

impl UnicodeString {
    pub(crate) fn read_string<Platform: RawPointerProvider>(self) -> Result<String, NtStatus> {
        if !self.length.is_multiple_of(2) {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        if self.length == 0 {
            return Ok(String::new());
        }
        if self.buffer == 0 {
            return Err(NtStatus::ACCESS_VIOLATION);
        }

        let chars = usize::from(self.length / 2);
        let buffer =
            <Platform as litebox::platform::RawPointerProvider>::RawConstPointer::<u16>::from_usize(
                self.buffer,
            );
        let Some(units) = buffer.to_owned_slice(chars) else {
            return Err(NtStatus::ACCESS_VIOLATION);
        };
        Ok(String::from_utf16_lossy(&units))
    }
}
