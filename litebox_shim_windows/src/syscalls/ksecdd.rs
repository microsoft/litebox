// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec;
use core::mem::size_of;

use int_enum::IntEnum;
use litebox::platform::{RawConstPointer as _, RawMutPointer as _};
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::nt_types::IoStatusBlock;
use crate::syscalls::Handle;
use crate::{
    ConstPtr, MutPtr, probe_guest_output_buffer, probe_guest_output_preserving_value, write_slice,
};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KsecIoControlCode {
    RandomFillBuffer = IOCTL_KSEC_RANDOM_FILL_BUFFER,
    CngRequest = IOCTL_KSEC_CNG_REQUEST,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KsecCngOperation {
    DeriveKey = KSEC_CNG_DERIVE_KEY,
    ResolveProviders = KSEC_CNG_RESOLVE_PROVIDERS,
}

pub(crate) const IOCTL_KSEC_RANDOM_FILL_BUFFER: u32 = 0x0039_0008;
pub(crate) const IOCTL_KSEC_CNG_REQUEST: u32 = 0x0039_0400;
pub(crate) const KSEC_CNG_DERIVE_KEY: u32 = 0x0001_0500;
pub(crate) const KSEC_CNG_RESOLVE_PROVIDERS: u32 = 0x0002_0000;
const KSEC_CNG_REQUEST_MAGIC: u32 = 0x1a2b_3c4d;
const KSEC_CNG_OUTPUT_SIZE: usize = size_of::<usize>();

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
struct KsecCngRequestHeader {
    magic: u32,
    operation: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct KsecCngDeriveKeyRequest {
    pub(crate) magic: u32,
    pub(crate) operation: u32,
    // TODO(ksecdd-cng): Name and implement these operation-specific arguments when a guest
    // exercises derive-key work rather than the initialization-time capability request.
    pub(crate) opaque_arguments: [usize; 11],
    pub(crate) event_handle: Handle,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct KsecCngResolveProvidersRequest {
    pub(crate) magic: u32,
    pub(crate) operation: u32,
    pub(crate) provider_type: usize,
    pub(crate) interface: usize,
    pub(crate) function_name_offset: usize,
    pub(crate) provider_name_offset: usize,
    pub(crate) mode: u32,
    pub(crate) flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
struct KsecCngProviderResponsePrefix {
    provider_count: u32,
    operation: u32,
    provider_refs_offset: usize,
    provider_ref_offset: usize,
    interface: u32,
    flags: u32,
    function_name_offset: usize,
    provider_name_offset: usize,
    reserved_0: usize,
    reserved_1: usize,
    image_ref_offset: usize,
    reserved_2: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
struct KsecCngImageRef {
    image_name_offset: usize,
    flags: u32,
    reserved: u32,
}

const KSEC_CNG_PROVIDER_RESPONSE_SIZE: usize = 216;
const KSEC_CNG_PROVIDER_REFS_OFFSET: usize = 16;
const KSEC_CNG_PROVIDER_REF_OFFSET: usize = 24;
const KSEC_CNG_FUNCTION_NAME_OFFSET: usize = 80;
const KSEC_CNG_PROVIDER_NAME_OFFSET: usize = 88;
const KSEC_CNG_IMAGE_REF_OFFSET: usize = 152;
const KSEC_CNG_IMAGE_NAME_OFFSET: usize = 168;
const KSEC_CNG_INTERFACE_RNG: usize = 6;
const KSEC_CNG_USER_MODE: usize = 1;

const _: () = assert!(size_of::<KsecCngDeriveKeyRequest>() == 104);
const _: () = assert!(size_of::<KsecCngResolveProvidersRequest>() == 48);
const _: () = assert!(size_of::<KsecCngProviderResponsePrefix>() == 80);
const _: () = assert!(size_of::<KsecCngImageRef>() == 16);

#[expect(
    clippy::too_many_arguments,
    reason = "device I/O control parameters preserve the Windows syscall ABI"
)]
pub(crate) fn handle_ioctl<Platform: crate::ShimPlatform>(
    platform: &Platform,
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    io_control_code: u32,
    input_buffer: Option<ConstPtr<Platform, u8>>,
    input_buffer_length: u32,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_buffer_length: u32,
    validate_cng_event: impl FnOnce(Handle) -> Result<(), NtStatus>,
) -> NtStatus {
    let Ok(io_control_code) = KsecIoControlCode::try_from(io_control_code) else {
        litebox_util_log::debug!(
            io_control_code:% = format_args!("{io_control_code:#x}"),
            input_buffer_length,
            output_buffer_length;
            "Unsupported KsecDD IOCTL"
        );
        return complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_SUPPORTED, 0);
    };

    match io_control_code {
        KsecIoControlCode::RandomFillBuffer => {
            litebox_util_log::debug!(
                input_buffer_length,
                output_buffer_length;
                "Handling KsecDD random-fill IOCTL"
            );
            let input_length = input_buffer_length as usize;
            if input_length != 0
                && input_buffer
                    .and_then(|buffer| buffer.to_owned_slice(input_length))
                    .is_none()
            {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
            }

            let output_length = output_buffer_length as usize;
            let Some(output_buffer) = output_buffer.filter(|_| output_length != 0) else {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::INVALID_PARAMETER, 0);
            };
            if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, output_length)
            {
                return complete_ioctl::<Platform>(io_status_block, status, 0);
            }

            let mut random = vec![0; output_length];
            platform.fill_bytes_crng(&mut random);
            if write_slice::<Platform, u8>(output_buffer.as_usize(), &random).is_none() {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
            }
            complete_ioctl::<Platform>(io_status_block, NtStatus::SUCCESS, output_length)
        }
        KsecIoControlCode::CngRequest => {
            let input_length = input_buffer_length as usize;
            if input_length < size_of::<KsecCngRequestHeader>() {
                return complete_ioctl::<Platform>(
                    io_status_block,
                    NtStatus::INFO_LENGTH_MISMATCH,
                    0,
                );
            }
            let Some(input_buffer) = input_buffer else {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
            };
            let header =
                ConstPtr::<Platform, KsecCngRequestHeader>::from_usize(input_buffer.as_usize());
            let Some(header) = header.read_at_offset(0) else {
                return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
            };
            if header.magic != KSEC_CNG_REQUEST_MAGIC {
                return complete_ioctl::<Platform>(
                    io_status_block,
                    NtStatus::INVALID_DEVICE_REQUEST,
                    0,
                );
            }
            let Ok(operation) = KsecCngOperation::try_from(header.operation) else {
                litebox_util_log::debug!(
                    operation:% = format_args!("{:#x}", header.operation),
                    input_buffer_length,
                    output_buffer_length;
                    "Unsupported KsecDD CNG operation"
                );
                return complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_SUPPORTED, 0);
            };

            match operation {
                KsecCngOperation::DeriveKey => handle_cng_derive_key::<Platform>(
                    io_status_block,
                    input_buffer,
                    input_length,
                    output_buffer,
                    output_buffer_length as usize,
                    validate_cng_event,
                ),
                KsecCngOperation::ResolveProviders => handle_cng_resolve_providers::<Platform>(
                    io_status_block,
                    input_buffer,
                    input_length,
                    output_buffer,
                    output_buffer_length as usize,
                ),
            }
        }
    }
}

fn handle_cng_derive_key<Platform: crate::ShimPlatform>(
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    input_buffer: ConstPtr<Platform, u8>,
    input_length: usize,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_length: usize,
    validate_event: impl FnOnce(Handle) -> Result<(), NtStatus>,
) -> NtStatus {
    if input_length != size_of::<KsecCngDeriveKeyRequest>() {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::INFO_LENGTH_MISMATCH, 0);
    }
    if output_length != KSEC_CNG_OUTPUT_SIZE {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::BUFFER_TOO_SMALL, 0);
    }
    let Some(output_buffer) = output_buffer else {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    };
    if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, KSEC_CNG_OUTPUT_SIZE)
    {
        return complete_ioctl::<Platform>(io_status_block, status, 0);
    }
    let request =
        ConstPtr::<Platform, KsecCngDeriveKeyRequest>::from_usize(input_buffer.as_usize());
    let Some(request) = request.read_at_offset(0) else {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    };
    if let Err(status) = validate_event(request.event_handle) {
        return complete_ioctl::<Platform>(io_status_block, status, 0);
    }
    complete_ioctl::<Platform>(io_status_block, NtStatus::SUCCESS, 0)
}

fn handle_cng_resolve_providers<Platform: crate::ShimPlatform>(
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    input_buffer: ConstPtr<Platform, u8>,
    input_length: usize,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_length: usize,
) -> NtStatus {
    if input_length < size_of::<KsecCngResolveProvidersRequest>() {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::INFO_LENGTH_MISMATCH, 0);
    }
    let Some(input) = input_buffer.to_owned_slice(input_length) else {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    };
    let request =
        ConstPtr::<Platform, KsecCngResolveProvidersRequest>::from_usize(input_buffer.as_usize());
    let Some(request) = request.read_at_offset(0) else {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    };

    let resolves_rng = (request.interface == KSEC_CNG_INTERFACE_RNG
        && request.function_name_offset == usize::MAX)
        || (request.interface == 0
            && request.function_name_offset != usize::MAX
            && matches_utf16_at_offset(&input, request.function_name_offset, "RNG"));
    if request.provider_type != usize::MAX
        || !resolves_rng
        || request.provider_name_offset != usize::MAX
        || usize::try_from(request.mode).unwrap() & KSEC_CNG_USER_MODE == 0
    {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::NOT_FOUND, 0);
    }
    if output_length < 8 {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::BUFFER_TOO_SMALL, 0);
    }
    let Some(output_buffer) = output_buffer else {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    };
    if output_length < KSEC_CNG_PROVIDER_RESPONSE_SIZE {
        if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, 8) {
            return complete_ioctl::<Platform>(io_status_block, status, 0);
        }
        let mut short_response = [0u8; 8];
        short_response[..4].copy_from_slice(&NtStatus::BUFFER_TOO_SMALL.as_raw().to_le_bytes());
        short_response[4..].copy_from_slice(
            &u32::try_from(KSEC_CNG_PROVIDER_RESPONSE_SIZE)
                .unwrap()
                .to_le_bytes(),
        );
        if write_slice::<Platform, u8>(output_buffer.as_usize(), &short_response).is_none() {
            return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
        }
        return complete_ioctl::<Platform>(io_status_block, NtStatus::BUFFER_OVERFLOW, 8);
    }
    if let Err(status) =
        probe_guest_output_buffer::<Platform>(output_buffer, KSEC_CNG_PROVIDER_RESPONSE_SIZE)
    {
        return complete_ioctl::<Platform>(io_status_block, status, 0);
    }

    let mut response = vec![0; KSEC_CNG_PROVIDER_RESPONSE_SIZE];
    let prefix = KsecCngProviderResponsePrefix {
        provider_count: 1,
        operation: KSEC_CNG_RESOLVE_PROVIDERS,
        provider_refs_offset: KSEC_CNG_PROVIDER_REFS_OFFSET,
        provider_ref_offset: KSEC_CNG_PROVIDER_REF_OFFSET,
        interface: KSEC_CNG_INTERFACE_RNG.try_into().unwrap(),
        flags: if request.interface == 0 { 0 } else { u32::MAX },
        function_name_offset: KSEC_CNG_FUNCTION_NAME_OFFSET,
        provider_name_offset: KSEC_CNG_PROVIDER_NAME_OFFSET,
        reserved_0: if request.interface == 0 {
            0x0000_0047_0000_0000
        } else {
            0
        },
        reserved_1: usize::MAX,
        image_ref_offset: KSEC_CNG_IMAGE_REF_OFFSET,
        reserved_2: usize::MAX,
    };
    response[..size_of::<KsecCngProviderResponsePrefix>()].copy_from_slice(prefix.as_bytes());
    write_utf16(&mut response, KSEC_CNG_FUNCTION_NAME_OFFSET, "RNG");
    write_utf16(
        &mut response,
        KSEC_CNG_PROVIDER_NAME_OFFSET,
        "Microsoft Primitive Provider",
    );
    let image_ref = KsecCngImageRef {
        image_name_offset: KSEC_CNG_IMAGE_NAME_OFFSET,
        flags: KSEC_CNG_USER_MODE.try_into().unwrap(),
        reserved: 0,
    };
    response[KSEC_CNG_IMAGE_REF_OFFSET..KSEC_CNG_IMAGE_NAME_OFFSET]
        .copy_from_slice(image_ref.as_bytes());
    write_utf16(
        &mut response,
        KSEC_CNG_IMAGE_NAME_OFFSET,
        "bcryptprimitives.dll",
    );

    if write_slice::<Platform, u8>(output_buffer.as_usize(), &response).is_none() {
        return complete_ioctl::<Platform>(io_status_block, NtStatus::ACCESS_VIOLATION, 0);
    }
    complete_ioctl::<Platform>(
        io_status_block,
        NtStatus::SUCCESS,
        KSEC_CNG_PROVIDER_RESPONSE_SIZE,
    )
}

fn write_utf16(buffer: &mut [u8], offset: usize, value: &str) {
    for (index, unit) in value.encode_utf16().chain(core::iter::once(0)).enumerate() {
        let start = offset + index * size_of::<u16>();
        buffer[start..start + size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
    }
}

fn matches_utf16_at_offset(buffer: &[u8], offset: usize, expected: &str) -> bool {
    if !offset.is_multiple_of(size_of::<u16>()) {
        return false;
    }
    let expected = expected.encode_utf16().chain(core::iter::once(0));
    expected.enumerate().all(|(index, expected)| {
        let Some(start) = index
            .checked_mul(size_of::<u16>())
            .and_then(|index| offset.checked_add(index))
        else {
            return false;
        };
        let Some(bytes) = buffer.get(start..start + size_of::<u16>()) else {
            return false;
        };
        u16::from_le_bytes(bytes.try_into().unwrap()) == expected
    })
}

fn complete_ioctl<Platform: crate::ShimPlatform>(
    io_status_block: MutPtr<Platform, IoStatusBlock>,
    status: NtStatus,
    information: usize,
) -> NtStatus {
    if probe_guest_output_preserving_value::<Platform, IoStatusBlock>(io_status_block).is_err()
        || io_status_block
            .write_at_offset(0, IoStatusBlock::new(status, information))
            .is_none()
    {
        return NtStatus::ACCESS_VIOLATION;
    }
    status
}
