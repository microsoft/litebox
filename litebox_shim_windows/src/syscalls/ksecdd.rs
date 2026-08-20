// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::{align_of, offset_of, size_of};

use int_enum::IntEnum;
use litebox::platform::RawConstPointer as _;
use litebox_common_windows::nt_status::NtStatus;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::syscalls::{Handle, IoStatus};
use crate::{ConstPtr, MutPtr, probe_guest_output_buffer, write_slice};

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
pub(crate) enum KsecIoControlCode {
    RandomFillBuffer = 0x0039_0008,
    CngRequest = 0x0039_0400,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
pub(crate) enum KsecCngOperation {
    Initialize = 0x0001_0500,
    ResolveProviders = 0x0002_0000,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, IntEnum, PartialEq)]
enum KsecCngInterface {
    Rng = 0x0000_0006,
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct KsecCngMode: u32 {
        const USER = 0x1;
    }
}

const KSEC_CNG_REQUEST_MAGIC: u32 = 0x1a2b_3c4d;
const KSEC_RANDOM_CHUNK_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct KsecCngRequestHeader {
    pub(crate) magic: u32,
    pub(crate) operation: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable)]
pub(crate) struct KsecCngInitializeRequest {
    pub(crate) header: KsecCngRequestHeader,
    // TODO(ksecdd-cng): Name these operation-specific arguments.
    pub(crate) opaque_arguments: [usize; 11],
    pub(crate) event_handle: Handle,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, FromBytes, Immutable, IntoBytes)]
pub(crate) struct KsecCngResolveProvidersRequest {
    pub(crate) header: KsecCngRequestHeader,
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
    property_count: u32,
    padding: u32,
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

#[repr(C)]
#[derive(Clone, Copy, Debug, Immutable, IntoBytes)]
struct KsecCngBufferTooSmallResponse {
    status: i32,
    required_size: u32,
}

pub(crate) fn handle_ioctl<Platform: crate::ShimPlatform>(
    platform: &Platform,
    io_control_code: u32,
    input_buffer: Option<ConstPtr<Platform, u8>>,
    input_buffer_length: u32,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_buffer_length: u32,
    validate_cng_event: impl FnOnce(Handle) -> Result<(), NtStatus>,
) -> IoStatus {
    let Ok(io_control_code) = KsecIoControlCode::try_from(io_control_code) else {
        litebox_util_log::debug!(
            io_control_code:% = format_args!("{io_control_code:#x}"),
            input_buffer_length,
            output_buffer_length;
            "Unsupported KsecDD IOCTL"
        );
        return IoStatus::failure(NtStatus::NOT_SUPPORTED);
    };

    match io_control_code {
        KsecIoControlCode::RandomFillBuffer => {
            let output_length = output_buffer_length as usize;
            let Some(output_buffer) = output_buffer.filter(|_| output_length != 0) else {
                return IoStatus::failure(NtStatus::INVALID_PARAMETER);
            };
            let output_address = output_buffer.as_usize();
            if output_address.checked_add(output_length).is_none() {
                return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
            }
            if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, output_length)
            {
                return IoStatus::failure(status);
            }

            let mut random = [0; KSEC_RANDOM_CHUNK_SIZE];
            let mut offset = 0;
            while offset < output_length {
                let chunk_length = (output_length - offset).min(random.len());
                platform.fill_bytes_crng(&mut random[..chunk_length]);
                if write_slice::<Platform, u8>(output_address + offset, &random[..chunk_length])
                    .is_none()
                {
                    return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
                }
                offset += chunk_length;
            }
            IoStatus::success(output_length)
        }
        KsecIoControlCode::CngRequest => {
            let input_length = input_buffer_length as usize;
            if input_length < size_of::<KsecCngRequestHeader>() {
                return IoStatus::failure(NtStatus::INFO_LENGTH_MISMATCH);
            }
            let Some(input_buffer) = input_buffer else {
                return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
            };
            let header =
                ConstPtr::<Platform, KsecCngRequestHeader>::from_usize(input_buffer.as_usize());
            let Some(header) = header.read_at_offset(0) else {
                return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
            };
            if header.magic != KSEC_CNG_REQUEST_MAGIC {
                return IoStatus::failure(NtStatus::INVALID_DEVICE_REQUEST);
            }
            let Ok(operation) = KsecCngOperation::try_from(header.operation) else {
                litebox_util_log::debug!(
                    operation:% = format_args!("{:#x}", header.operation),
                    input_buffer_length,
                    output_buffer_length;
                    "Unsupported KsecDD CNG operation"
                );
                return IoStatus::failure(NtStatus::NOT_SUPPORTED);
            };

            match operation {
                KsecCngOperation::Initialize => handle_cng_initialize::<Platform>(
                    input_buffer,
                    input_length,
                    output_buffer,
                    output_buffer_length as usize,
                    validate_cng_event,
                ),
                KsecCngOperation::ResolveProviders => handle_cng_resolve_providers::<Platform>(
                    input_buffer,
                    input_length,
                    output_buffer,
                    output_buffer_length as usize,
                ),
            }
        }
    }
}

fn handle_cng_initialize<Platform: crate::ShimPlatform>(
    input_buffer: ConstPtr<Platform, u8>,
    input_length: usize,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_length: usize,
    validate_event: impl FnOnce(Handle) -> Result<(), NtStatus>,
) -> IoStatus {
    if input_length != size_of::<KsecCngInitializeRequest>() {
        return IoStatus::failure(NtStatus::INFO_LENGTH_MISMATCH);
    }
    if output_length != size_of::<usize>() {
        return IoStatus::failure(NtStatus::BUFFER_TOO_SMALL);
    }
    let Some(output_buffer) = output_buffer else {
        return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
    };
    if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, size_of::<usize>()) {
        return IoStatus::failure(status);
    }
    let request =
        ConstPtr::<Platform, KsecCngInitializeRequest>::from_usize(input_buffer.as_usize());
    let Some(request) = request.read_at_offset(0) else {
        return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
    };
    if let Err(status) = validate_event(request.event_handle) {
        return IoStatus::failure(status);
    }
    // The observed CNG initialization request only requires validating its event handle.
    IoStatus::success(0)
}

fn handle_cng_resolve_providers<Platform: crate::ShimPlatform>(
    input_buffer: ConstPtr<Platform, u8>,
    input_length: usize,
    output_buffer: Option<MutPtr<Platform, u8>>,
    output_length: usize,
) -> IoStatus {
    if input_length < size_of::<KsecCngResolveProvidersRequest>() {
        return IoStatus::failure(NtStatus::INFO_LENGTH_MISMATCH);
    }
    let request =
        ConstPtr::<Platform, KsecCngResolveProvidersRequest>::from_usize(input_buffer.as_usize());
    let Some(request) = request.read_at_offset(0) else {
        return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
    };

    let infer_interface = request.interface == 0;
    let interface = u32::try_from(request.interface)
        .ok()
        .and_then(|interface| KsecCngInterface::try_from(interface).ok());
    let function_name = (infer_interface && request.function_name_offset != usize::MAX)
        .then(|| {
            read_utf16_at_offset::<Platform>(
                input_buffer,
                input_length,
                request.function_name_offset,
                "RNG".len(),
            )
        })
        .flatten();
    let resolves_rng = match interface {
        Some(KsecCngInterface::Rng) => request.function_name_offset == usize::MAX,
        None if infer_interface => function_name.as_deref() == Some("RNG"),
        None => false,
    };
    let mode = KsecCngMode::from_bits_retain(request.mode);
    if !resolves_rng {
        litebox_util_log::debug!(
            interface:% = format_args!("{:#x}", request.interface),
            function_name:? = function_name.as_deref();
            "Unsupported KsecDD CNG interface or function"
        );
        return IoStatus::failure(NtStatus::NOT_FOUND);
    }
    if request.provider_type != usize::MAX
        || request.provider_name_offset != usize::MAX
        || !mode.contains(KsecCngMode::USER)
    {
        return IoStatus::failure(NtStatus::NOT_FOUND);
    }

    let mut response = vec![0; size_of::<KsecCngProviderResponsePrefix>()];
    let function_name_offset = append_utf16(&mut response, "RNG");
    let provider_name_offset = append_utf16(&mut response, "Microsoft Primitive Provider");

    let image_ref_offset = response
        .len()
        .next_multiple_of(align_of::<KsecCngImageRef>());
    response.resize(image_ref_offset + size_of::<KsecCngImageRef>(), 0);
    let image_name_offset = append_utf16(&mut response, "bcryptprimitives.dll");
    let image_ref = KsecCngImageRef {
        image_name_offset,
        flags: KsecCngMode::USER.bits(),
        reserved: 0,
    };
    response[image_ref_offset..image_name_offset].copy_from_slice(image_ref.as_bytes());

    let response_size = response.len().next_multiple_of(align_of::<usize>());
    response.resize(response_size, 0);
    let prefix = KsecCngProviderResponsePrefix {
        provider_count: 1,
        operation: KsecCngOperation::ResolveProviders as u32,
        provider_refs_offset: offset_of!(KsecCngProviderResponsePrefix, provider_ref_offset),
        provider_ref_offset: offset_of!(KsecCngProviderResponsePrefix, interface),
        interface: KsecCngInterface::Rng as u32,
        flags: if infer_interface { 0 } else { u32::MAX },
        function_name_offset,
        provider_name_offset,
        property_count: 0,
        padding: 0,
        reserved_1: usize::MAX,
        image_ref_offset,
        reserved_2: usize::MAX,
    };
    response[..size_of::<KsecCngProviderResponsePrefix>()].copy_from_slice(prefix.as_bytes());

    if output_length < size_of::<KsecCngBufferTooSmallResponse>() {
        return IoStatus::failure(NtStatus::BUFFER_TOO_SMALL);
    }
    let Some(output_buffer) = output_buffer else {
        return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
    };
    if output_length < response.len() {
        if let Err(status) = probe_guest_output_buffer::<Platform>(
            output_buffer,
            size_of::<KsecCngBufferTooSmallResponse>(),
        ) {
            return IoStatus::failure(status);
        }
        let short_response = KsecCngBufferTooSmallResponse {
            status: NtStatus::BUFFER_TOO_SMALL.as_raw(),
            required_size: response.len().try_into().unwrap(),
        };
        if write_slice::<Platform, u8>(output_buffer.as_usize(), short_response.as_bytes())
            .is_none()
        {
            return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
        }
        return IoStatus::with_information(
            NtStatus::BUFFER_OVERFLOW,
            size_of::<KsecCngBufferTooSmallResponse>(),
        );
    }
    if let Err(status) = probe_guest_output_buffer::<Platform>(output_buffer, response.len()) {
        return IoStatus::failure(status);
    }

    if write_slice::<Platform, u8>(output_buffer.as_usize(), &response).is_none() {
        return IoStatus::failure(NtStatus::ACCESS_VIOLATION);
    }
    IoStatus::success(response.len())
}

fn append_utf16(buffer: &mut Vec<u8>, value: &str) -> usize {
    let offset = buffer.len();
    for unit in value.encode_utf16().chain(core::iter::once(0)) {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    offset
}

fn read_utf16_at_offset<Platform: crate::ShimPlatform>(
    buffer: ConstPtr<Platform, u8>,
    buffer_length: usize,
    offset: usize,
    maximum_characters: usize,
) -> Option<String> {
    if !offset.is_multiple_of(size_of::<u16>()) {
        return None;
    }
    let byte_length = maximum_characters
        .checked_add(1)
        .and_then(|units| units.checked_mul(size_of::<u16>()))?;
    let end = offset.checked_add(byte_length)?;
    if end > buffer_length {
        return None;
    }
    let address = buffer.as_usize().checked_add(offset)?;
    let bytes = ConstPtr::<Platform, u8>::from_usize(address).to_owned_slice(byte_length)?;
    let units = bytes
        .chunks_exact(size_of::<u16>())
        .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap()))
        .collect::<alloc::vec::Vec<_>>();
    let terminator = units.iter().position(|&unit| unit == 0)?;
    String::from_utf16(&units[..terminator]).ok()
}
