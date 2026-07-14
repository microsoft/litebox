// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows console driver support.

use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::IoStatusBlock;
use crate::{ConstPtr, MutPtr};

const FILE_DEVICE_CONSOLE: u32 = 0x50;
const CD_SERVER_EA_NAME: &[u8] = b"server";

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
pub(crate) enum CondrvObject {
    Input = 0,
    Output = 1,
    Server = 2,
    Reference = 3,
    Connect = 4,
}

impl CondrvObject {
    pub(crate) fn from_device_name(name: &str) -> Result<Self, NtStatus> {
        match Self::from_component(name) {
            Some(object @ (Self::Input | Self::Output | Self::Server)) => Ok(object),
            Some(Self::Reference) => Err(NtStatus::INVALID_HANDLE),
            Some(Self::Connect) => Err(NtStatus::OBJECT_TYPE_MISMATCH),
            None => Err(NtStatus::OBJECT_NAME_NOT_FOUND),
        }
    }

    fn from_component(name: &str) -> Option<Self> {
        if name.eq_ignore_ascii_case("Input") {
            Some(Self::Input)
        } else if name.eq_ignore_ascii_case("Output") {
            Some(Self::Output)
        } else if name.eq_ignore_ascii_case("Server") {
            Some(Self::Server)
        } else if name.eq_ignore_ascii_case("Reference") {
            Some(Self::Reference)
        } else if name.eq_ignore_ascii_case("Connect") {
            Some(Self::Connect)
        } else {
            None
        }
    }

    pub(crate) fn relative_child(self, name: &str) -> Result<Self, NtStatus> {
        let name = name.strip_prefix('\\').ok_or(NtStatus::NOT_FOUND)?;
        let child = Self::from_component(name).ok_or(NtStatus::NOT_FOUND)?;

        match (self, child) {
            (Self::Server, Self::Server | Self::Reference)
            | (Self::Reference, Self::Server | Self::Connect | Self::Input | Self::Output)
            | (Self::Input | Self::Output, Self::Server | Self::Input | Self::Output) => Ok(child),
            (Self::Server, Self::Input | Self::Output) => Err(NtStatus::INVALID_DEVICE_STATE),
            (Self::Reference | Self::Input | Self::Output, Self::Reference) => {
                Err(NtStatus::OBJECT_TYPE_MISMATCH)
            }
            (Self::Server | Self::Input | Self::Output, Self::Connect) | (Self::Connect, _) => {
                Err(NtStatus::INVALID_HANDLE)
            }
        }
    }

    pub(crate) fn handle_path(self) -> &'static str {
        match self {
            Self::Input => "/dev/stdin",
            Self::Output => "/dev/stdout",
            Self::Server => r"\Device\ConDrv\Server",
            Self::Reference => r"\Device\ConDrv\Reference",
            Self::Connect => r"\Device\ConDrv\Connect",
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum IoControlMethod {
    Buffered = 0,
    InDirect = 1,
    OutDirect = 2,
    Neither = 3,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct IoControlAccess: u32 {
        const ANY = 0;
        const READ = 1;
        const WRITE = 2;
        const _ = !0;
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum ConsoleIoControlFunction {
    LaunchServer = 13,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
struct FileFullEaInformation {
    next_entry_offset: u32,
    flags: u8,
    ea_name_length: u8,
    ea_value_length: u16,
}

#[cfg(test)]
pub(crate) fn ea_buffer(name: &[u8], value_length: usize) -> alloc::vec::Vec<u8> {
    let header = FileFullEaInformation {
        next_entry_offset: 0,
        flags: 0,
        ea_name_length: u8::try_from(name.len()).unwrap(),
        ea_value_length: u16::try_from(value_length).unwrap(),
    };
    let mut buffer = alloc::vec::Vec::new();
    buffer.extend_from_slice(header.as_bytes());
    buffer.extend_from_slice(name);
    buffer.push(0);
    buffer.resize(buffer.len() + value_length, 0);
    buffer
}

pub(crate) fn validate_connect_server_ea<Platform: crate::ShimPlatform>(
    ea_buffer: Option<ConstPtr<Platform, u8>>,
    ea_length: u32,
) -> Result<(), NtStatus> {
    let Some(ea_buffer) = ea_buffer else {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    };
    let ea_length = ea_length as usize;
    let Some(entry) = ConstPtr::<Platform, FileFullEaInformation>::from_usize(ea_buffer.as_usize())
        .read_at_offset(0)
    else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };

    let name_offset = size_of::<FileFullEaInformation>();
    let name_length = entry.ea_name_length as usize;
    let value_length = entry.ea_value_length as usize;
    let value_offset = name_offset
        .checked_add(name_length)
        .and_then(|offset| offset.checked_add(1))
        .ok_or(NtStatus::EAS_NOT_SUPPORTED)?;
    let entry_length = value_offset
        .checked_add(value_length)
        .ok_or(NtStatus::EAS_NOT_SUPPORTED)?;
    if entry_length > ea_length {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    }

    let Some(name_address) = ea_buffer.as_usize().checked_add(name_offset) else {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    };
    let Some(name_with_nul) =
        ConstPtr::<Platform, u8>::from_usize(name_address).to_owned_slice(name_length + 1)
    else {
        return Err(NtStatus::ACCESS_VIOLATION);
    };
    let Some((&0, name)) = name_with_nul.split_last() else {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    };
    if !name.eq_ignore_ascii_case(CD_SERVER_EA_NAME) {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    }

    let Some(value_address) = ea_buffer.as_usize().checked_add(value_offset) else {
        return Err(NtStatus::EAS_NOT_SUPPORTED);
    };
    // The ConDrv "server" EA value format is undocumented; probe the declared payload without
    // interpreting it until its semantics are understood.
    if ConstPtr::<Platform, u8>::from_usize(value_address)
        .to_owned_slice(value_length)
        .is_none()
    {
        return Err(NtStatus::ACCESS_VIOLATION);
    }

    Ok(())
}

pub(crate) fn handle_ioctl<Platform: crate::ShimPlatform>(
    condrv_object: CondrvObject,
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    io_control_code: u32,
    input_buffer: Option<ConstPtr<Platform, u8>>,
    input_buffer_length: u32,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_buffer_length: u32,
) -> NtStatus {
    let device_type = io_control_code >> 16;
    let access = IoControlAccess::from_bits_retain((io_control_code >> 14) & 0x3);
    let function = (io_control_code >> 2) & 0xfff;
    let method = IoControlMethod::try_from(io_control_code & 0x3);

    if device_type != FILE_DEVICE_CONSOLE || method != Ok(IoControlMethod::Neither) {
        litebox_util_log::debug!(
            condrv_object:? = condrv_object,
            io_control_code:% = format_args!("{io_control_code:#x}");
            "Unsupported ConDrv IOCTL shape"
        );
        return complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_SUPPORTED, 0);
    }

    let Ok(function) = ConsoleIoControlFunction::try_from(function) else {
        litebox_util_log::debug!(
            condrv_object:? = condrv_object,
            io_control_code:% = format_args!("{io_control_code:#x}");
            "Unsupported ConDrv IOCTL function"
        );
        return complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_SUPPORTED, 0);
    };

    match (condrv_object, function) {
        (CondrvObject::Server, ConsoleIoControlFunction::LaunchServer)
            if access.is_empty()
                && input_buffer.is_some()
                && input_buffer_length != 0
                && output_buffer.is_none()
                && output_buffer_length == 0 =>
        {
            if input_buffer
                .and_then(|input_buffer| input_buffer.read_at_offset(0))
                .is_none()
            {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
            }
            complete_ioctl::<Platform>(io_status_block, NtStatus::SUCCESS, 0)
        }
        _ => {
            litebox_util_log::debug!(
                condrv_object:? = condrv_object,
                function:? = function,
                io_control_code:% = format_args!("{io_control_code:#x}");
                "Unsupported ConDrv IOCTL for object"
            );
            complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_SUPPORTED, 0)
        }
    }
}

pub(crate) fn complete_ioctl<Platform: crate::ShimPlatform>(
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    status: NtStatus,
    information: usize,
) -> NtStatus {
    if io_status_block
        .write_at_offset(0, IoStatusBlock::new(status, information))
        .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_children_match_host_parse_contexts() {
        use CondrvObject::{Connect, Input, Output, Reference, Server};

        for (parent, name, expected) in [
            (Server, r"\Server", Ok(Server)),
            (Server, r"\Reference", Ok(Reference)),
            (Server, r"\Connect", Err(NtStatus::INVALID_HANDLE)),
            (Server, r"\Input", Err(NtStatus::INVALID_DEVICE_STATE)),
            (Server, r"\Output", Err(NtStatus::INVALID_DEVICE_STATE)),
            (Reference, r"\Server", Ok(Server)),
            (Reference, r"\Connect", Ok(Connect)),
            (Reference, r"\Input", Ok(Input)),
            (Reference, r"\Output", Ok(Output)),
            (
                Reference,
                r"\Reference",
                Err(NtStatus::OBJECT_TYPE_MISMATCH),
            ),
            (Input, r"\Server", Ok(Server)),
            (Input, r"\Input", Ok(Input)),
            (Input, r"\Output", Ok(Output)),
            (Input, r"\Reference", Err(NtStatus::OBJECT_TYPE_MISMATCH)),
            (Input, r"\Connect", Err(NtStatus::INVALID_HANDLE)),
            (Output, r"\Server", Ok(Server)),
            (Output, r"\Input", Ok(Input)),
            (Output, r"\Output", Ok(Output)),
            (Output, r"\Reference", Err(NtStatus::OBJECT_TYPE_MISMATCH)),
            (Output, r"\Connect", Err(NtStatus::INVALID_HANDLE)),
        ] {
            assert_eq!(parent.relative_child(name), expected, "{parent:?} + {name}");
        }

        assert_eq!(Server.relative_child("Reference"), Err(NtStatus::NOT_FOUND));
        assert_eq!(Server.relative_child(r"\Missing"), Err(NtStatus::NOT_FOUND));
    }
}
