// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use crate::fs::{
    ChmodFileRequest, ChownFileRequest, FileAccessMode, FileError, FileMode, FileNodeInfo,
    FileOpenFlags, FileSeekWhence, FileStatus, FileUser, HandleFileStatusRequest, MkdirFileRequest,
    OpenFileRequest, OpenFileResponse, PathFileStatusRequest, ReadDirectoryRequest,
    ReadDirectoryResponse, ReadFileRequest, ReadFileResponse, RmdirFileRequest, SeekFileRequest,
    SeekFileResponse, TruncateFileRequest, UnlinkFileRequest, WriteFileRequest, WriteFileResponse,
    file_type_from_raw, file_type_raw,
};
use crate::message::{FileRequest, FileResponse};

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
const RESPONSE_TAG_PATH_STATUS: u8 = 6;
const RESPONSE_TAG_HANDLE_STATUS: u8 = 7;
const RESPONSE_TAG_CHMOD: u8 = 8;
const RESPONSE_TAG_CHOWN: u8 = 9;
const RESPONSE_TAG_UNLINK: u8 = 10;
const RESPONSE_TAG_MKDIR: u8 = 11;
const RESPONSE_TAG_RMDIR: u8 = 12;
const RESPONSE_TAG_FAILED: u8 = u8::MAX;

const _: () = {
    assert!(REQUEST_TAG_OPEN == RESPONSE_TAG_OPEN);
    assert!(REQUEST_TAG_READ == RESPONSE_TAG_READ);
    assert!(REQUEST_TAG_WRITE == RESPONSE_TAG_WRITE);
    assert!(REQUEST_TAG_SEEK == RESPONSE_TAG_SEEK);
    assert!(REQUEST_TAG_TRUNCATE == RESPONSE_TAG_TRUNCATE);
    assert!(REQUEST_TAG_READ_DIRECTORY == RESPONSE_TAG_READ_DIRECTORY);
    assert!(REQUEST_TAG_PATH_STATUS == RESPONSE_TAG_PATH_STATUS);
    assert!(REQUEST_TAG_HANDLE_STATUS == RESPONSE_TAG_HANDLE_STATUS);
    assert!(REQUEST_TAG_CHMOD == RESPONSE_TAG_CHMOD);
    assert!(REQUEST_TAG_CHOWN == RESPONSE_TAG_CHOWN);
    assert!(REQUEST_TAG_UNLINK == RESPONSE_TAG_UNLINK);
    assert!(REQUEST_TAG_MKDIR == RESPONSE_TAG_MKDIR);
    assert!(REQUEST_TAG_RMDIR == RESPONSE_TAG_RMDIR);
};

pub(super) fn encode_fs_request(encoder: &mut Encoder, request: FileRequest) {
    match request {
        FileRequest::Open(request) => {
            encoder.u8(REQUEST_TAG_OPEN);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encode_access_mode(encoder, request.access);
            encoder.u16(request.flags.bits());
            encoder.u16(request.mode.bits());
        }
        FileRequest::Read(request) => {
            encoder.u8(REQUEST_TAG_READ);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encode_optional_u64(encoder, request.offset);
        }
        FileRequest::Write(request) => {
            encoder.u8(REQUEST_TAG_WRITE);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encode_optional_u64(encoder, request.offset);
        }
        FileRequest::Seek(request) => {
            encoder.u8(REQUEST_TAG_SEEK);
            encoder.handle(request.handle);
            encoder.u64(request.offset.cast_unsigned());
            encode_whence(encoder, request.whence);
        }
        FileRequest::Truncate(request) => {
            encoder.u8(REQUEST_TAG_TRUNCATE);
            encoder.handle(request.handle);
            encoder.u64(request.length);
            encoder.u8(u8::from(request.reset_offset));
        }
        FileRequest::ReadDirectory(request) => {
            encoder.u8(REQUEST_TAG_READ_DIRECTORY);
            encoder.handle(request.handle);
            encoder.shared_buffer_descriptor(request.buffer);
            encoder.u64(request.start_index);
        }
        FileRequest::PathStatus(request) => {
            encoder.u8(REQUEST_TAG_PATH_STATUS);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
        FileRequest::HandleStatus(request) => {
            encoder.u8(REQUEST_TAG_HANDLE_STATUS);
            encoder.handle(request.handle);
        }
        FileRequest::Chmod(request) => {
            encoder.u8(REQUEST_TAG_CHMOD);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encoder.u16(request.mode.bits());
        }
        FileRequest::Chown(request) => {
            encoder.u8(REQUEST_TAG_CHOWN);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.acting_user);
            encode_optional_u16(encoder, request.user);
            encode_optional_u16(encoder, request.group);
        }
        FileRequest::Unlink(request) => {
            encoder.u8(REQUEST_TAG_UNLINK);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
        FileRequest::Mkdir(request) => {
            encoder.u8(REQUEST_TAG_MKDIR);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
            encoder.u16(request.mode.bits());
        }
        FileRequest::Rmdir(request) => {
            encoder.u8(REQUEST_TAG_RMDIR);
            encoder.shared_buffer_descriptor(request.path);
            encode_user(encoder, request.user);
        }
    }
}

fn decode_mode(decoder: &mut Decoder<'_>) -> Result<FileMode, WireError> {
    FileMode::from_bits(decoder.u16()?).ok_or(WireError::InvalidTag)
}

pub(super) fn decode_fs_request(decoder: &mut Decoder<'_>) -> Result<FileRequest, WireError> {
    match decoder.u8()? {
        REQUEST_TAG_OPEN => Ok(FileRequest::Open(OpenFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            access: decode_access_mode(decoder)?,
            flags: FileOpenFlags::from_bits(decoder.u16()?).ok_or(WireError::InvalidTag)?,
            mode: decode_mode(decoder)?,
        })),
        REQUEST_TAG_READ => Ok(FileRequest::Read(ReadFileRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            offset: decode_optional_u64(decoder)?,
        })),
        REQUEST_TAG_WRITE => Ok(FileRequest::Write(WriteFileRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            offset: decode_optional_u64(decoder)?,
        })),
        REQUEST_TAG_SEEK => Ok(FileRequest::Seek(SeekFileRequest {
            handle: decoder.handle()?,
            offset: decoder.u64()?.cast_signed(),
            whence: decode_whence(decoder)?,
        })),
        REQUEST_TAG_TRUNCATE => Ok(FileRequest::Truncate(TruncateFileRequest {
            handle: decoder.handle()?,
            length: decoder.u64()?,
            reset_offset: decode_bool(decoder)?,
        })),
        REQUEST_TAG_READ_DIRECTORY => Ok(FileRequest::ReadDirectory(ReadDirectoryRequest {
            handle: decoder.handle()?,
            buffer: decoder.shared_buffer_descriptor()?,
            start_index: decoder.u64()?,
        })),
        REQUEST_TAG_PATH_STATUS => Ok(FileRequest::PathStatus(PathFileStatusRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        REQUEST_TAG_HANDLE_STATUS => Ok(FileRequest::HandleStatus(HandleFileStatusRequest {
            handle: decoder.handle()?,
        })),
        REQUEST_TAG_CHMOD => Ok(FileRequest::Chmod(ChmodFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            mode: decode_mode(decoder)?,
        })),
        REQUEST_TAG_CHOWN => Ok(FileRequest::Chown(ChownFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            acting_user: decode_user(decoder)?,
            user: decode_optional_u16(decoder)?,
            group: decode_optional_u16(decoder)?,
        })),
        REQUEST_TAG_UNLINK => Ok(FileRequest::Unlink(UnlinkFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        REQUEST_TAG_MKDIR => Ok(FileRequest::Mkdir(MkdirFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
            mode: decode_mode(decoder)?,
        })),
        REQUEST_TAG_RMDIR => Ok(FileRequest::Rmdir(RmdirFileRequest {
            path: decoder.shared_buffer_descriptor()?,
            user: decode_user(decoder)?,
        })),
        _ => Err(WireError::InvalidTag),
    }
}

pub(super) fn encode_fs_response(encoder: &mut Encoder, response: FileResponse) {
    match response {
        FileResponse::Open(OpenFileResponse { handle }) => {
            encoder.u8(RESPONSE_TAG_OPEN);
            encoder.handle(handle);
        }
        FileResponse::Read(ReadFileResponse { read }) => {
            encoder.u8(RESPONSE_TAG_READ);
            encoder.u32(read);
        }
        FileResponse::Write(WriteFileResponse { written }) => {
            encoder.u8(RESPONSE_TAG_WRITE);
            encoder.u32(written);
        }
        FileResponse::Seek(SeekFileResponse { offset }) => {
            encoder.u8(RESPONSE_TAG_SEEK);
            encoder.u64(offset);
        }
        FileResponse::Truncate => encoder.u8(RESPONSE_TAG_TRUNCATE),
        FileResponse::ReadDirectory(ReadDirectoryResponse { length, next_index }) => {
            encoder.u8(RESPONSE_TAG_READ_DIRECTORY);
            encoder.u32(length);
            encode_optional_u64(encoder, next_index);
        }
        FileResponse::PathStatus(status) => {
            encoder.u8(RESPONSE_TAG_PATH_STATUS);
            encode_status(encoder, status);
        }
        FileResponse::HandleStatus(status) => {
            encoder.u8(RESPONSE_TAG_HANDLE_STATUS);
            encode_status(encoder, status);
        }
        FileResponse::Chmod => encoder.u8(RESPONSE_TAG_CHMOD),
        FileResponse::Chown => encoder.u8(RESPONSE_TAG_CHOWN),
        FileResponse::Unlink => encoder.u8(RESPONSE_TAG_UNLINK),
        FileResponse::Mkdir => encoder.u8(RESPONSE_TAG_MKDIR),
        FileResponse::Rmdir => encoder.u8(RESPONSE_TAG_RMDIR),
        FileResponse::Failed(error) => {
            encoder.u8(RESPONSE_TAG_FAILED);
            encode_file_error(encoder, error);
        }
    }
}

pub(super) fn decode_fs_response(decoder: &mut Decoder<'_>) -> Result<FileResponse, WireError> {
    match decoder.u8()? {
        RESPONSE_TAG_OPEN => Ok(FileResponse::Open(OpenFileResponse {
            handle: decoder.handle()?,
        })),
        RESPONSE_TAG_READ => Ok(FileResponse::Read(ReadFileResponse {
            read: decoder.u32()?,
        })),
        RESPONSE_TAG_WRITE => Ok(FileResponse::Write(WriteFileResponse {
            written: decoder.u32()?,
        })),
        RESPONSE_TAG_SEEK => Ok(FileResponse::Seek(SeekFileResponse {
            offset: decoder.u64()?,
        })),
        RESPONSE_TAG_TRUNCATE => Ok(FileResponse::Truncate),
        RESPONSE_TAG_READ_DIRECTORY => Ok(FileResponse::ReadDirectory(ReadDirectoryResponse {
            length: decoder.u32()?,
            next_index: decode_optional_u64(decoder)?,
        })),
        RESPONSE_TAG_PATH_STATUS => Ok(FileResponse::PathStatus(decode_status(decoder)?)),
        RESPONSE_TAG_HANDLE_STATUS => Ok(FileResponse::HandleStatus(decode_status(decoder)?)),
        RESPONSE_TAG_CHMOD => Ok(FileResponse::Chmod),
        RESPONSE_TAG_CHOWN => Ok(FileResponse::Chown),
        RESPONSE_TAG_UNLINK => Ok(FileResponse::Unlink),
        RESPONSE_TAG_MKDIR => Ok(FileResponse::Mkdir),
        RESPONSE_TAG_RMDIR => Ok(FileResponse::Rmdir),
        RESPONSE_TAG_FAILED => Ok(FileResponse::Failed(decode_file_error(decoder)?)),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_file_error(encoder: &mut Encoder, error: FileError) {
    encoder.u8(match error {
        FileError::AccessNotAllowed => 1,
        FileError::NoWritePermissions => 2,
        FileError::ReadOnlyFs => 3,
        FileError::AlreadyExists => 4,
        FileError::Io => 5,
        FileError::NoSuchFileOrDirectory => 6,
        FileError::NoSearchPermissions => 7,
        FileError::InvalidPathname => 8,
        FileError::MissingComponent => 9,
        FileError::ComponentNotDirectory => 10,
        FileError::NotFile => 11,
        FileError::NotForReading => 12,
        FileError::NotForWriting => 13,
        FileError::InvalidOffset => 14,
        FileError::NonSeekable => 15,
        FileError::IsDirectory => 16,
        FileError::IsTerminalDevice => 17,
        FileError::NotOwner => 18,
        FileError::NotDirectory => 19,
        FileError::Busy => 20,
        FileError::NotEmpty => 21,
    });
}

fn decode_file_error(decoder: &mut Decoder<'_>) -> Result<FileError, WireError> {
    match decoder.u8()? {
        1 => Ok(FileError::AccessNotAllowed),
        2 => Ok(FileError::NoWritePermissions),
        3 => Ok(FileError::ReadOnlyFs),
        4 => Ok(FileError::AlreadyExists),
        5 => Ok(FileError::Io),
        6 => Ok(FileError::NoSuchFileOrDirectory),
        7 => Ok(FileError::NoSearchPermissions),
        8 => Ok(FileError::InvalidPathname),
        9 => Ok(FileError::MissingComponent),
        10 => Ok(FileError::ComponentNotDirectory),
        11 => Ok(FileError::NotFile),
        12 => Ok(FileError::NotForReading),
        13 => Ok(FileError::NotForWriting),
        14 => Ok(FileError::InvalidOffset),
        15 => Ok(FileError::NonSeekable),
        16 => Ok(FileError::IsDirectory),
        17 => Ok(FileError::IsTerminalDevice),
        18 => Ok(FileError::NotOwner),
        19 => Ok(FileError::NotDirectory),
        20 => Ok(FileError::Busy),
        21 => Ok(FileError::NotEmpty),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_user(encoder: &mut Encoder, user: FileUser) {
    encoder.u16(user.user);
    encoder.u16(user.group);
}

fn decode_user(decoder: &mut Decoder<'_>) -> Result<FileUser, WireError> {
    Ok(FileUser {
        user: decoder.u16()?,
        group: decoder.u16()?,
    })
}

fn encode_access_mode(encoder: &mut Encoder, access: FileAccessMode) {
    encoder.u8(match access {
        FileAccessMode::ReadOnly => 0,
        FileAccessMode::WriteOnly => 1,
        FileAccessMode::ReadWrite => 2,
    });
}

fn decode_access_mode(decoder: &mut Decoder<'_>) -> Result<FileAccessMode, WireError> {
    match decoder.u8()? {
        0 => Ok(FileAccessMode::ReadOnly),
        1 => Ok(FileAccessMode::WriteOnly),
        2 => Ok(FileAccessMode::ReadWrite),
        _ => Err(WireError::InvalidTag),
    }
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

fn encode_whence(encoder: &mut Encoder, whence: FileSeekWhence) {
    encoder.u8(match whence {
        FileSeekWhence::Beginning => 0,
        FileSeekWhence::Current => 1,
        FileSeekWhence::End => 2,
    });
}

fn decode_whence(decoder: &mut Decoder<'_>) -> Result<FileSeekWhence, WireError> {
    match decoder.u8()? {
        0 => Ok(FileSeekWhence::Beginning),
        1 => Ok(FileSeekWhence::Current),
        2 => Ok(FileSeekWhence::End),
        _ => Err(WireError::InvalidTag),
    }
}

fn encode_status(encoder: &mut Encoder, status: FileStatus) {
    encoder.u8(file_type_raw(status.file_type));
    encoder.u16(status.mode.bits());
    encoder.u64(status.size);
    encode_user(encoder, status.owner);
    encoder.u64(status.node_info.dev);
    encoder.u64(status.node_info.ino);
    encode_optional_u64(encoder, status.node_info.rdev);
    encoder.u64(status.block_size);
}

fn decode_status(decoder: &mut Decoder<'_>) -> Result<FileStatus, WireError> {
    let file_type = file_type_from_raw(decoder.u8()?).ok_or(WireError::InvalidTag)?;
    let mode = decode_mode(decoder)?;
    let size = decoder.u64()?;
    let owner = decode_user(decoder)?;
    let dev = decoder.u64()?;
    let ino = decoder.u64()?;
    let rdev = decode_optional_u64(decoder)?;
    let block_size = decoder.u64()?;
    Ok(FileStatus {
        file_type,
        mode,
        size,
        owner,
        node_info: FileNodeInfo { dev, ino, rdev },
        block_size,
    })
}
