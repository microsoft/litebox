// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::filesystem::{
    ChmodFileRequest, ChownFileRequest, FilesystemError, FilesystemFileStatus, FilesystemNamespace,
    FilesystemNodeInfo, FilesystemSeekWhence, FilesystemUser, HandleFileStatusRequest,
    MkdirFileRequest, OpenFileRequest, OpenFileResponse, PathFileStatusRequest,
    ReadDirectoryRequest, ReadDirectoryResponse, ReadFileRequest, ReadFileResponse,
    RmdirFileRequest, SeekFileRequest, SeekFileResponse, TruncateFileRequest, UnlinkFileRequest,
    WriteFileRequest, WriteFileResponse, file_type_from_raw, file_type_raw,
};
use crate::message::{FilesystemRequest, FilesystemResponse};

use super::{
    WireError,
    primitive::{Decoder, Encoder},
};

const REQUEST_TAG_OPEN: u8 = 0;
const REQUEST_TAG_READ: u8 = 1;
const REQUEST_TAG_WRITE: u8 = 2;
const REQUEST_TAG_SEEK: u8 = 3;
const REQUEST_TAG_TRUNCATE: u8 = 4;
const REQUEST_TAG_READ_DIRECTORY: u8 = 5;
const REQUEST_TAG_PATH_STATUS: u8 = 6;
const REQUEST_TAG_HANDLE_STATUS: u8 = 7;
const REQUEST_TAG_CHMOD: u8 = 8;
const REQUEST_TAG_CHOWN: u8 = 9;
const REQUEST_TAG_UNLINK: u8 = 10;
const REQUEST_TAG_MKDIR: u8 = 11;
const REQUEST_TAG_RMDIR: u8 = 12;

const RESPONSE_TAG_OPEN: u8 = 0;
const RESPONSE_TAG_READ: u8 = 1;
const RESPONSE_TAG_WRITE: u8 = 2;
const RESPONSE_TAG_SEEK: u8 = 3;
const RESPONSE_TAG_TRUNCATE: u8 = 4;
const RESPONSE_TAG_READ_DIRECTORY: u8 = 5;
const RESPONSE_TAG_STATUS: u8 = 6;
const RESPONSE_TAG_CHMOD: u8 = 7;
const RESPONSE_TAG_CHOWN: u8 = 8;
const RESPONSE_TAG_UNLINK: u8 = 9;
const RESPONSE_TAG_MKDIR: u8 = 10;
const RESPONSE_TAG_RMDIR: u8 = 11;
const RESPONSE_TAG_FAILED: u8 = 12;

pub(super) fn encode_filesystem_request(encoder: &mut Encoder, request: FilesystemRequest) {
    match request {
        FilesystemRequest::Open(request) => {
            encoder.u8(REQUEST_TAG_OPEN);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encoder.u32(request.flags);
            encoder.u32(request.mode);
        }
        FilesystemRequest::Read(request) => {
            encoder.u8(REQUEST_TAG_READ);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encode_optional_u64(encoder, request.offset);
        }
        FilesystemRequest::Write(request) => {
            encoder.u8(REQUEST_TAG_WRITE);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encode_optional_u64(encoder, request.offset);
        }
        FilesystemRequest::Seek(request) => {
            encoder.u8(REQUEST_TAG_SEEK);
            encoder.handle(request.handle);
            encoder.u64(request.offset.cast_unsigned());
            encode_whence(encoder, request.whence);
        }
        FilesystemRequest::Truncate(request) => {
            encoder.u8(REQUEST_TAG_TRUNCATE);
            encoder.handle(request.handle);
            encoder.u64(request.length);
            encoder.u8(u8::from(request.reset_offset));
        }
        FilesystemRequest::ReadDirectory(request) => {
            encoder.u8(REQUEST_TAG_READ_DIRECTORY);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encoder.u64(request.start_index);
        }
        FilesystemRequest::PathStatus(request) => {
            encoder.u8(REQUEST_TAG_PATH_STATUS);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
        FilesystemRequest::HandleStatus(request) => {
            encoder.u8(REQUEST_TAG_HANDLE_STATUS);
            encoder.handle(request.handle);
        }
        FilesystemRequest::Chmod(request) => {
            encoder.u8(REQUEST_TAG_CHMOD);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encoder.u32(request.mode);
        }
        FilesystemRequest::Chown(request) => {
            encoder.u8(REQUEST_TAG_CHOWN);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.acting_user);
            encode_optional_u16(encoder, request.user);
            encode_optional_u16(encoder, request.group);
        }
        FilesystemRequest::Unlink(request) => {
            encoder.u8(REQUEST_TAG_UNLINK);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
        FilesystemRequest::Mkdir(request) => {
            encoder.u8(REQUEST_TAG_MKDIR);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encoder.u32(request.mode);
        }
        FilesystemRequest::Rmdir(request) => {
            encoder.u8(REQUEST_TAG_RMDIR);
            encode_namespace(encoder, request.namespace);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
    }
}

pub(super) fn decode_filesystem_request(
    decoder: &mut Decoder<'_>,
) -> Result<FilesystemRequest, WireError> {
    match decoder.u8()? {
        REQUEST_TAG_OPEN => Ok(FilesystemRequest::Open(OpenFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            flags: decoder.u32()?,
            mode: decoder.u32()?,
        })),
        REQUEST_TAG_READ => Ok(FilesystemRequest::Read(ReadFileRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            offset: decode_optional_u64(decoder)?,
        })),
        REQUEST_TAG_WRITE => Ok(FilesystemRequest::Write(WriteFileRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            offset: decode_optional_u64(decoder)?,
        })),
        REQUEST_TAG_SEEK => Ok(FilesystemRequest::Seek(SeekFileRequest {
            handle: decoder.handle()?,
            offset: decoder.u64()?.cast_signed(),
            whence: decode_whence(decoder)?,
        })),
        REQUEST_TAG_TRUNCATE => Ok(FilesystemRequest::Truncate(TruncateFileRequest {
            handle: decoder.handle()?,
            length: decoder.u64()?,
            reset_offset: decode_bool(decoder)?,
        })),
        REQUEST_TAG_READ_DIRECTORY => Ok(FilesystemRequest::ReadDirectory(ReadDirectoryRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            start_index: decoder.u64()?,
        })),
        REQUEST_TAG_PATH_STATUS => Ok(FilesystemRequest::PathStatus(PathFileStatusRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        REQUEST_TAG_HANDLE_STATUS => Ok(FilesystemRequest::HandleStatus(HandleFileStatusRequest {
            handle: decoder.handle()?,
        })),
        REQUEST_TAG_CHMOD => Ok(FilesystemRequest::Chmod(ChmodFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            mode: decoder.u32()?,
        })),
        REQUEST_TAG_CHOWN => Ok(FilesystemRequest::Chown(ChownFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            acting_user: decode_user(decoder)?,
            user: decode_optional_u16(decoder)?,
            group: decode_optional_u16(decoder)?,
        })),
        REQUEST_TAG_UNLINK => Ok(FilesystemRequest::Unlink(UnlinkFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        REQUEST_TAG_MKDIR => Ok(FilesystemRequest::Mkdir(MkdirFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            mode: decoder.u32()?,
        })),
        REQUEST_TAG_RMDIR => Ok(FilesystemRequest::Rmdir(RmdirFileRequest {
            namespace: decode_namespace(decoder)?,
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_filesystem_response(encoder: &mut Encoder, response: FilesystemResponse) {
    match response {
        FilesystemResponse::Open(OpenFileResponse { handle }) => {
            encoder.u8(RESPONSE_TAG_OPEN);
            encoder.handle(handle);
        }
        FilesystemResponse::Read(ReadFileResponse { read }) => {
            encoder.u8(RESPONSE_TAG_READ);
            encoder.u32(read);
        }
        FilesystemResponse::Write(WriteFileResponse { written }) => {
            encoder.u8(RESPONSE_TAG_WRITE);
            encoder.u32(written);
        }
        FilesystemResponse::Seek(SeekFileResponse { offset }) => {
            encoder.u8(RESPONSE_TAG_SEEK);
            encoder.u64(offset);
        }
        FilesystemResponse::Truncate => encoder.u8(RESPONSE_TAG_TRUNCATE),
        FilesystemResponse::ReadDirectory(ReadDirectoryResponse { length, next_index }) => {
            encoder.u8(RESPONSE_TAG_READ_DIRECTORY);
            encoder.u32(length);
            encode_optional_u64(encoder, next_index);
        }
        FilesystemResponse::Status(status) => {
            encoder.u8(RESPONSE_TAG_STATUS);
            encode_status(encoder, status);
        }
        FilesystemResponse::Chmod => encoder.u8(RESPONSE_TAG_CHMOD),
        FilesystemResponse::Chown => encoder.u8(RESPONSE_TAG_CHOWN),
        FilesystemResponse::Unlink => encoder.u8(RESPONSE_TAG_UNLINK),
        FilesystemResponse::Mkdir => encoder.u8(RESPONSE_TAG_MKDIR),
        FilesystemResponse::Rmdir => encoder.u8(RESPONSE_TAG_RMDIR),
        FilesystemResponse::Failed(error) => {
            encoder.u8(RESPONSE_TAG_FAILED);
            encoder.u8(error.as_raw());
        }
    }
}

pub(super) fn decode_filesystem_response(
    decoder: &mut Decoder<'_>,
) -> Result<FilesystemResponse, WireError> {
    match decoder.u8()? {
        RESPONSE_TAG_OPEN => Ok(FilesystemResponse::Open(OpenFileResponse {
            handle: decoder.handle()?,
        })),
        RESPONSE_TAG_READ => Ok(FilesystemResponse::Read(ReadFileResponse {
            read: decoder.u32()?,
        })),
        RESPONSE_TAG_WRITE => Ok(FilesystemResponse::Write(WriteFileResponse {
            written: decoder.u32()?,
        })),
        RESPONSE_TAG_SEEK => Ok(FilesystemResponse::Seek(SeekFileResponse {
            offset: decoder.u64()?,
        })),
        RESPONSE_TAG_TRUNCATE => Ok(FilesystemResponse::Truncate),
        RESPONSE_TAG_READ_DIRECTORY => {
            Ok(FilesystemResponse::ReadDirectory(ReadDirectoryResponse {
                length: decoder.u32()?,
                next_index: decode_optional_u64(decoder)?,
            }))
        }
        RESPONSE_TAG_STATUS => Ok(FilesystemResponse::Status(decode_status(decoder)?)),
        RESPONSE_TAG_CHMOD => Ok(FilesystemResponse::Chmod),
        RESPONSE_TAG_CHOWN => Ok(FilesystemResponse::Chown),
        RESPONSE_TAG_UNLINK => Ok(FilesystemResponse::Unlink),
        RESPONSE_TAG_MKDIR => Ok(FilesystemResponse::Mkdir),
        RESPONSE_TAG_RMDIR => Ok(FilesystemResponse::Rmdir),
        RESPONSE_TAG_FAILED => Ok(FilesystemResponse::Failed(
            FilesystemError::from_raw(decoder.u8()?).ok_or(WireError::InvalidTag)?,
        )),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_user(encoder: &mut Encoder, user: FilesystemUser) {
    encoder.u16(user.user);
    encoder.u16(user.group);
}

fn decode_user(decoder: &mut Decoder<'_>) -> Result<FilesystemUser, WireError> {
    Ok(FilesystemUser {
        user: decoder.u16()?,
        group: decoder.u16()?,
    })
}

fn encode_optional_u16(encoder: &mut Encoder, value: Option<u16>) {
    match value {
        Some(value) => {
            encoder.u8(1);
            encoder.u16(value);
        }
        None => encoder.u8(0),
    }
}

fn decode_optional_u16(decoder: &mut Decoder<'_>) -> Result<Option<u16>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.u16()?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_optional_u64(encoder: &mut Encoder, value: Option<u64>) {
    match value {
        Some(value) => {
            encoder.u8(1);
            encoder.u64(value);
        }
        None => encoder.u8(0),
    }
}

fn decode_optional_u64(decoder: &mut Decoder<'_>) -> Result<Option<u64>, WireError> {
    match decoder.u8()? {
        0 => Ok(None),
        1 => Ok(Some(decoder.u64()?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn decode_bool(decoder: &mut Decoder<'_>) -> Result<bool, WireError> {
    match decoder.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_namespace(encoder: &mut Encoder, namespace: FilesystemNamespace) {
    encoder.u8(match namespace {
        FilesystemNamespace::Guest => 0,
        FilesystemNamespace::WindowsRegistry => 1,
    });
}

fn decode_namespace(decoder: &mut Decoder<'_>) -> Result<FilesystemNamespace, WireError> {
    match decoder.u8()? {
        0 => Ok(FilesystemNamespace::Guest),
        1 => Ok(FilesystemNamespace::WindowsRegistry),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_whence(encoder: &mut Encoder, whence: FilesystemSeekWhence) {
    encoder.u8(match whence {
        FilesystemSeekWhence::Beginning => 0,
        FilesystemSeekWhence::Current => 1,
        FilesystemSeekWhence::End => 2,
    });
}

fn decode_whence(decoder: &mut Decoder<'_>) -> Result<FilesystemSeekWhence, WireError> {
    match decoder.u8()? {
        0 => Ok(FilesystemSeekWhence::Beginning),
        1 => Ok(FilesystemSeekWhence::Current),
        2 => Ok(FilesystemSeekWhence::End),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_status(encoder: &mut Encoder, status: FilesystemFileStatus) {
    encoder.u8(file_type_raw(status.file_type));
    encoder.u32(status.mode);
    encoder.u64(status.size);
    encode_user(encoder, status.owner);
    encoder.u64(status.node_info.dev);
    encoder.u64(status.node_info.ino);
    encode_optional_u64(encoder, status.node_info.rdev);
    encoder.u64(status.block_size);
}

fn decode_status(decoder: &mut Decoder<'_>) -> Result<FilesystemFileStatus, WireError> {
    let file_type = file_type_from_raw(decoder.u8()?).ok_or(WireError::InvalidTag)?;
    let mode = decoder.u32()?;
    let size = decoder.u64()?;
    let owner = decode_user(decoder)?;
    let dev = decoder.u64()?;
    let ino = decoder.u64()?;
    let rdev = decode_optional_u64(decoder)?;
    let block_size = decoder.u64()?;
    Ok(FilesystemFileStatus {
        file_type,
        mode,
        size,
        owner,
        node_info: FilesystemNodeInfo { dev, ino, rdev },
        block_size,
    })
}
