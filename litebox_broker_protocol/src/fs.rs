// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker fs requests, responses, and ABI-neutral values.

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU64;

use bitflags::bitflags;
use thiserror::Error;

use crate::ObjectHandle;
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferDescriptor};

/// Maximum bytes transferred through one fs shared-buffer request.
///
/// This remains independent of slot capacity so increasing the shared-buffer
/// layout does not silently change fs protocol behavior.
pub const MAX_FILE_TRANSFER_SIZE: u32 = 64 * 1024;

const _: () = assert!(MAX_FILE_TRANSFER_SIZE <= SHARED_BUFFER_SLOT_SIZE);

/// File user identity used for permission checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileUser {
    /// Effective user ID.
    pub user: u16,
    /// Effective group ID.
    pub group: u16,
}

impl FileUser {
    /// The root user.
    pub const ROOT: Self = Self { user: 0, group: 0 };
}

/// File object kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Character device.
    CharacterDevice,
}

/// Device and inode identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileNodeInfo {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Nonzero referenced device number for special files.
    pub rdev: Option<NonZeroU64>,
}

/// Status returned for a fs object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStatus {
    /// Object kind.
    pub file_type: FileType,
    /// Permission and special mode bits, excluding object-type bits.
    pub mode: FileMode,
    /// Object size in bytes.
    pub size: u64,
    /// Owner identity.
    pub owner: FileUser,
    /// Device and inode identity.
    pub node_info: FileNodeInfo,
    /// Preferred fs I/O block size.
    pub block_size: u64,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDirectoryEntry {
    /// Entry name.
    pub name: String,
    /// Entry kind.
    pub file_type: FileType,
    /// Optional device and inode identity.
    pub node_info: Option<FileNodeInfo>,
}

/// File operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileError {
    #[error("requested access is not allowed")]
    AccessNotAllowed,
    #[error("parent directory does not allow writes")]
    NoWritePermissions,
    #[error("fs is read-only")]
    ReadOnlyFs,
    #[error("object already exists")]
    AlreadyExists,
    #[error("I/O error")]
    Io,
    #[error("no such file or directory")]
    NoSuchFileOrDirectory,
    #[error("directory search permission was denied")]
    NoSearchPermissions,
    #[error("invalid pathname")]
    InvalidPathname,
    #[error("a pathname component is missing")]
    MissingComponent,
    #[error("a pathname component is not a directory")]
    ComponentNotDirectory,
    #[error("object is not a file")]
    NotFile,
    #[error("object was not opened for reading")]
    NotForReading,
    #[error("object was not opened for writing")]
    NotForWriting,
    #[error("invalid file offset")]
    InvalidOffset,
    #[error("object is not seekable")]
    NonSeekable,
    #[error("object is a directory")]
    IsDirectory,
    #[error("object is a terminal device")]
    IsTerminalDevice,
    #[error("caller does not own the object")]
    NotOwner,
    #[error("object is not a directory")]
    NotDirectory,
    #[error("object is busy")]
    Busy,
    #[error("directory is not empty")]
    NotEmpty,
}

/// Seek origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileSeekWhence {
    /// Offset from the beginning of the file.
    RelativeToBeginning,
    /// Offset from the file's current position.
    RelativeToCurrentOffset,
    /// Offset from the end of the file.
    RelativeToEnd,
}

/// Access mode requested when opening a fs object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileAccessMode {
    /// Open for reading.
    ReadOnly,
    /// Open for writing.
    WriteOnly,
    /// Open for reading and writing.
    ReadWrite,
}

bitflags! {
    /// ABI-neutral fs permission and special mode bits.
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct FileMode: u16 {
        /// User (file owner) has read, write, and execute permission.
        const RWXU = 0o00700;
        /// User has read permission.
        const RUSR = 0o00400;
        /// User has write permission.
        const WUSR = 0o00200;
        /// User has execute permission.
        const XUSR = 0o00100;
        /// Group has read, write, and execute permission.
        const RWXG = 0o00070;
        /// Group has read permission.
        const RGRP = 0o00040;
        /// Group has write permission.
        const WGRP = 0o00020;
        /// Group has execute permission.
        const XGRP = 0o00010;
        /// Others have read, write, and execute permission.
        const RWXO = 0o00007;
        /// Others have read permission.
        const ROTH = 0o00004;
        /// Others have write permission.
        const WOTH = 0o00002;
        /// Others have execute permission.
        const XOTH = 0o00001;
        /// Set-user-ID bit.
        const SUID = 0o0004000;
        /// Set-group-ID bit.
        const SGID = 0o0002000;
        /// Sticky bit.
        const SVTX = 0o0001000;
        /// Every permission and special mode bit this protocol version defines.
        const SUPPORTED = 0o0007777;
    }
}

/// ABI-neutral fs open flags.
///
/// These values are intentionally independent of target-specific `O_*` bit
/// assignments.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileOpenFlags(u16);

impl FileOpenFlags {
    /// No open flags.
    pub const NONE: Self = Self(0);
    /// Create the object when it does not exist.
    pub const CREATE: Self = Self(1 << 0);
    /// Truncate an existing regular file.
    pub const TRUNCATE: Self = Self(1 << 1);
    /// Do not assign a controlling terminal.
    pub const NO_CONTROLLING_TERMINAL: Self = Self(1 << 2);
    /// Require creation to fail when the object already exists.
    pub const EXCLUSIVE: Self = Self(1 << 3);
    /// Require the opened object to be a directory.
    pub const DIRECTORY: Self = Self(1 << 4);
    /// Request nonblocking operation.
    pub const NONBLOCKING: Self = Self(1 << 5);
    /// Allow large-file operation.
    pub const LARGE_FILE: Self = Self(1 << 6);
    /// Do not follow the final symbolic link.
    pub const NO_FOLLOW: Self = Self(1 << 7);
    /// Append writes to the end of the file.
    pub const APPEND: Self = Self(1 << 8);
    /// Open only for path-based operations.
    pub const PATH: Self = Self(1 << 9);
    /// Every open flag this protocol version defines.
    pub const SUPPORTED: Self = Self(
        Self::CREATE.0
            | Self::TRUNCATE.0
            | Self::NO_CONTROLLING_TERMINAL.0
            | Self::EXCLUSIVE.0
            | Self::DIRECTORY.0
            | Self::NONBLOCKING.0
            | Self::LARGE_FILE.0
            | Self::NO_FOLLOW.0
            | Self::APPEND.0
            | Self::PATH.0,
    );

    /// Creates flags when every bit is defined by this protocol version.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::SUPPORTED.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Returns the stable protocol bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether all flags in `other` are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the union of two flag sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for FileOpenFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Opens or creates a fs object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// Requested access mode.
    pub access: FileAccessMode,
    /// Open flags.
    pub flags: FileOpenFlags,
    /// Creation mode.
    pub mode: FileMode,
}

/// Successful open response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFileResponse {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
}

/// Reads from an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadFileRequest {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
    /// Shared-buffer destination.
    pub buffer: SharedBufferDescriptor,
    /// Explicit offset, or `None` to use and update the shared position.
    pub offset: Option<u64>,
}

/// Successful read response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadFileResponse {
    /// Number of bytes read.
    pub read: u32,
}

/// Writes to an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFileRequest {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
    /// Shared-buffer source.
    pub buffer: SharedBufferDescriptor,
    /// Explicit offset, or `None` to use and update the shared position.
    pub offset: Option<u64>,
}

/// Successful write response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriteFileResponse {
    /// Number of bytes written.
    pub written: u32,
}

/// Repositions an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeekFileRequest {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
    /// Signed offset relative to `whence`.
    pub offset: i64,
    /// Seek origin.
    pub whence: FileSeekWhence,
}

/// Successful seek response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeekFileResponse {
    /// Resulting absolute position.
    pub offset: u64,
}

/// Truncates an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TruncateFileRequest {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
    /// New file length.
    pub length: u64,
    /// Whether to reset the shared position to zero.
    pub reset_offset: bool,
}

/// Reads one bounded page of directory entries into a shared-buffer region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadDirectoryRequest {
    /// Broker-owned directory handle.
    pub handle: ObjectHandle,
    /// Shared-buffer destination for encoded entries.
    pub buffer: SharedBufferDescriptor,
    /// Entry index at which this response should begin.
    pub start_index: u64,
}

/// Successful directory-read response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadDirectoryResponse {
    /// Encoded payload length.
    pub length: u32,
    /// Entry index for the next request, or `None` when this response is complete.
    pub next_index: Option<u64>,
}

/// Reads status by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathFileStatusRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Reads status by open handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleFileStatusRequest {
    /// Broker-owned file handle.
    pub handle: ObjectHandle,
}

/// Changes mode bits by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChmodFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// New mode bits.
    pub mode: FileMode,
}

/// Changes ownership by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChownFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub acting_user: FileUser,
    /// New user ID, if changed.
    pub user: Option<u16>,
    /// New group ID, if changed.
    pub group: Option<u16>,
}

/// Removes a file by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlinkFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Creates a directory by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MkdirFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// New directory mode.
    pub mode: FileMode,
}

/// Removes a directory by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RmdirFileRequest {
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Error while encoding or decoding a shared directory payload.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DirectoryPayloadError {
    #[error("directory payload is malformed")]
    Malformed,
    #[error("directory payload exceeds one fs transfer")]
    TooLarge,
}

/// Error while processing a directory payload for an fs transfer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectoryTransferError {
    #[error(transparent)]
    Payload(#[from] DirectoryPayloadError),
    #[error("directory payload allocation failed")]
    OutOfMemory,
}

impl DirectoryTransferError {
    fn into_payload_error(self) -> DirectoryPayloadError {
        match self {
            Self::Payload(error) => error,
            Self::OutOfMemory => DirectoryPayloadError::TooLarge,
        }
    }
}

/// Encodes directory entries for one fs shared-buffer transfer.
///
/// Allocation failures are reported as [`DirectoryPayloadError::TooLarge`] for
/// compatibility with the original codec API.
pub fn encode_directory_entries(
    entries: &[FileDirectoryEntry],
) -> Result<Vec<u8>, DirectoryPayloadError> {
    let (payload, next_index) =
        encode_directory_entries_chunk(entries, 0, MAX_FILE_TRANSFER_SIZE as usize)
            .map_err(DirectoryTransferError::into_payload_error)?;
    if next_index.is_some() {
        return Err(DirectoryPayloadError::TooLarge);
    }
    Ok(payload)
}

/// Encodes one directory-entry chunk no longer than `maximum_length`.
///
/// `start_index` and the returned continuation index count entries, not bytes.
pub fn encode_directory_entries_chunk(
    entries: &[FileDirectoryEntry],
    start_index: usize,
    maximum_length: usize,
) -> Result<(Vec<u8>, Option<u64>), DirectoryTransferError> {
    let (end_index, encoded_length) =
        directory_entries_chunk_end(entries, start_index, maximum_length)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(encoded_length)
        .map_err(|_| DirectoryTransferError::OutOfMemory)?;
    output.extend_from_slice(&0u32.to_le_bytes());
    for entry in &entries[start_index..end_index] {
        encode_directory_entry(&mut output, entry)?;
    }
    let count =
        u32::try_from(end_index - start_index).map_err(|_| DirectoryPayloadError::TooLarge)?;
    output[..size_of::<u32>()].copy_from_slice(&count.to_le_bytes());
    let next_index = if end_index == entries.len() {
        None
    } else {
        Some(u64::try_from(end_index).map_err(|_| DirectoryPayloadError::TooLarge)?)
    };
    Ok((output, next_index))
}

/// Decodes directory entries from one fs shared-buffer transfer.
///
/// Allocation failures are reported as [`DirectoryPayloadError::TooLarge`] for
/// compatibility with the original codec API.
pub fn decode_directory_entries(
    payload: &[u8],
) -> Result<Vec<FileDirectoryEntry>, DirectoryPayloadError> {
    try_decode_directory_entries(payload).map_err(DirectoryTransferError::into_payload_error)
}

/// Decodes directory entries while distinguishing allocation failure.
pub fn try_decode_directory_entries(
    payload: &[u8],
) -> Result<Vec<FileDirectoryEntry>, DirectoryTransferError> {
    const MINIMUM_ENTRY_LENGTH: usize = size_of::<u32>() + 2;

    if payload.len() > MAX_FILE_TRANSFER_SIZE as usize {
        return Err(DirectoryPayloadError::TooLarge.into());
    }
    let mut decoder = DirectoryPayloadDecoder { payload, offset: 0 };
    let count = decoder.u32()? as usize;
    if count > (decoder.payload.len() - decoder.offset) / MINIMUM_ENTRY_LENGTH {
        return Err(DirectoryPayloadError::Malformed.into());
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| DirectoryTransferError::OutOfMemory)?;
    for _ in 0..count {
        let name_len = decoder.u32()? as usize;
        let encoded_name = core::str::from_utf8(decoder.take(name_len)?)
            .map_err(|_| DirectoryPayloadError::Malformed)?;
        let mut name = String::new();
        name.try_reserve_exact(encoded_name.len())
            .map_err(|_| DirectoryTransferError::OutOfMemory)?;
        name.push_str(encoded_name);
        let file_type =
            file_type_from_raw(decoder.u8()?).ok_or(DirectoryPayloadError::Malformed)?;
        let node_info = match decoder.u8()? {
            0 => None,
            1 => {
                let dev = decoder.u64()?;
                let ino = decoder.u64()?;
                let rdev = match decoder.u8()? {
                    0 => None,
                    1 => Some(
                        NonZeroU64::new(decoder.u64()?).ok_or(DirectoryPayloadError::Malformed)?,
                    ),
                    _ => return Err(DirectoryPayloadError::Malformed.into()),
                };
                Some(FileNodeInfo { dev, ino, rdev })
            }
            _ => return Err(DirectoryPayloadError::Malformed.into()),
        };
        entries.push(FileDirectoryEntry {
            name,
            file_type,
            node_info,
        });
    }
    if decoder.offset != payload.len() {
        return Err(DirectoryPayloadError::Malformed.into());
    }
    Ok(entries)
}

pub(crate) const fn file_type_raw(file_type: FileType) -> u8 {
    match file_type {
        FileType::RegularFile => 0,
        FileType::Directory => 1,
        FileType::CharacterDevice => 2,
    }
}

pub(crate) const fn file_type_from_raw(raw: u8) -> Option<FileType> {
    match raw {
        0 => Some(FileType::RegularFile),
        1 => Some(FileType::Directory),
        2 => Some(FileType::CharacterDevice),
        _ => None,
    }
}

fn encoded_directory_entry_length(
    entry: &FileDirectoryEntry,
) -> Result<usize, DirectoryPayloadError> {
    let _ = u32::try_from(entry.name.len()).map_err(|_| DirectoryPayloadError::TooLarge)?;
    size_of::<u32>()
        .checked_add(entry.name.len())
        .and_then(|length| length.checked_add(2))
        .and_then(|length| {
            entry.node_info.map_or(Some(length), |node_info| {
                length
                    .checked_add(size_of::<u64>() * 2 + 1)
                    .and_then(|length| {
                        node_info
                            .rdev
                            .map_or(Some(length), |_| length.checked_add(size_of::<u64>()))
                    })
            })
        })
        .ok_or(DirectoryPayloadError::TooLarge)
}

fn directory_entries_chunk_end(
    entries: &[FileDirectoryEntry],
    start_index: usize,
    maximum_length: usize,
) -> Result<(usize, usize), DirectoryPayloadError> {
    if start_index > entries.len()
        || !(size_of::<u32>()..=MAX_FILE_TRANSFER_SIZE as usize).contains(&maximum_length)
    {
        return Err(DirectoryPayloadError::TooLarge);
    }
    let mut encoded_length = size_of::<u32>();
    let mut end_index = start_index;
    while let Some(entry) = entries.get(end_index) {
        encoded_length = encoded_length
            .checked_add(encoded_directory_entry_length(entry)?)
            .ok_or(DirectoryPayloadError::TooLarge)?;
        if encoded_length > maximum_length {
            if end_index == start_index {
                return Err(DirectoryPayloadError::TooLarge);
            }
            encoded_length -= encoded_directory_entry_length(entry)?;
            break;
        }
        end_index += 1;
    }
    Ok((end_index, encoded_length))
}

fn encode_directory_entry(
    output: &mut Vec<u8>,
    entry: &FileDirectoryEntry,
) -> Result<(), DirectoryPayloadError> {
    let name = entry.name.as_bytes();
    let name_len = u32::try_from(name.len()).map_err(|_| DirectoryPayloadError::TooLarge)?;
    output.extend_from_slice(&name_len.to_le_bytes());
    output.extend_from_slice(name);
    output.push(file_type_raw(entry.file_type));
    match entry.node_info {
        Some(node_info) => {
            output.push(1);
            output.extend_from_slice(&node_info.dev.to_le_bytes());
            output.extend_from_slice(&node_info.ino.to_le_bytes());
            match node_info.rdev {
                Some(rdev) => {
                    output.push(1);
                    output.extend_from_slice(&rdev.get().to_le_bytes());
                }
                None => output.push(0),
            }
        }
        None => output.push(0),
    }
    Ok(())
}

struct DirectoryPayloadDecoder<'a> {
    payload: &'a [u8],
    offset: usize,
}

impl<'a> DirectoryPayloadDecoder<'a> {
    fn u8(&mut self) -> Result<u8, DirectoryPayloadError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DirectoryPayloadError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, DirectoryPayloadError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DirectoryPayloadError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(DirectoryPayloadError::Malformed)?;
        let bytes = self
            .payload
            .get(self.offset..end)
            .ok_or(DirectoryPayloadError::Malformed)?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn directory_payload_round_trips_all_entry_shapes() {
        let entries = vec![
            FileDirectoryEntry {
                name: ".".into(),
                file_type: FileType::Directory,
                node_info: None,
            },
            FileDirectoryEntry {
                name: "regular".into(),
                file_type: FileType::RegularFile,
                node_info: Some(FileNodeInfo {
                    dev: 2,
                    ino: 3,
                    rdev: None,
                }),
            },
            FileDirectoryEntry {
                name: "device".into(),
                file_type: FileType::CharacterDevice,
                node_info: Some(FileNodeInfo {
                    dev: 5,
                    ino: 7,
                    rdev: NonZeroU64::new(11),
                }),
            },
        ];

        let payload = encode_directory_entries(&entries).unwrap();
        assert_eq!(decode_directory_entries(&payload).unwrap(), entries);
    }

    #[test]
    fn directory_payload_wire_shape_is_pinned() {
        let payload = encode_directory_entries(&[FileDirectoryEntry {
            name: "x".into(),
            file_type: FileType::CharacterDevice,
            node_info: Some(FileNodeInfo {
                dev: 2,
                ino: 3,
                rdev: NonZeroU64::new(5),
            }),
        }])
        .unwrap();
        assert_eq!(
            payload,
            [
                1, 0, 0, 0, 1, 0, 0, 0, b'x', 2, 1, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
                1, 5, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn directory_payload_chunks_use_entry_indexes() {
        let entries = [
            FileDirectoryEntry {
                name: "first".into(),
                file_type: FileType::RegularFile,
                node_info: None,
            },
            FileDirectoryEntry {
                name: "second".into(),
                file_type: FileType::Directory,
                node_info: None,
            },
            FileDirectoryEntry {
                name: "third".into(),
                file_type: FileType::CharacterDevice,
                node_info: None,
            },
        ];
        let first_two_length = encode_directory_entries(&entries[..2]).unwrap().len();

        let (first, next_index) =
            encode_directory_entries_chunk(&entries, 0, first_two_length).unwrap();
        assert_eq!(decode_directory_entries(&first).unwrap(), entries[..2]);
        assert_eq!(next_index, Some(2));

        let (last, next_index) =
            encode_directory_entries_chunk(&entries, 2, first_two_length).unwrap();
        assert_eq!(decode_directory_entries(&last).unwrap(), entries[2..]);
        assert_eq!(next_index, None);
    }

    #[test]
    fn directory_payload_preserves_full_width_node_info_and_rejects_zero_rdev() {
        let entries = [FileDirectoryEntry {
            name: "device".into(),
            file_type: FileType::CharacterDevice,
            node_info: Some(FileNodeInfo {
                dev: u64::MAX,
                ino: u64::MAX,
                rdev: Some(NonZeroU64::MAX),
            }),
        }];
        let mut payload = encode_directory_entries(&entries).unwrap();
        assert_eq!(decode_directory_entries(&payload).unwrap(), entries);

        let rdev_start = payload.len() - size_of::<u64>();
        payload[rdev_start..].fill(0);
        assert_eq!(
            decode_directory_entries(&payload),
            Err(DirectoryPayloadError::Malformed)
        );
    }

    #[test]
    fn directory_payload_rejects_malformed_data() {
        assert_eq!(
            decode_directory_entries(&u32::MAX.to_le_bytes()),
            Err(DirectoryPayloadError::Malformed)
        );

        let valid = encode_directory_entries(&[FileDirectoryEntry {
            name: "entry".into(),
            file_type: FileType::RegularFile,
            node_info: None,
        }])
        .unwrap();

        for length in 0..valid.len() {
            assert_eq!(
                decode_directory_entries(&valid[..length]),
                Err(DirectoryPayloadError::Malformed)
            );
        }

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(
            decode_directory_entries(&trailing),
            Err(DirectoryPayloadError::Malformed)
        );

        let mut invalid_utf8 = valid;
        invalid_utf8[8] = 0xff;
        assert_eq!(
            decode_directory_entries(&invalid_utf8),
            Err(DirectoryPayloadError::Malformed)
        );
    }

    #[test]
    fn directory_payload_is_bounded_by_one_transfer() {
        const ENTRY_OVERHEAD: usize = size_of::<u32>() + 2;
        let maximum_name_length =
            MAX_FILE_TRANSFER_SIZE as usize - size_of::<u32>() - ENTRY_OVERHEAD;
        let maximum_entry = FileDirectoryEntry {
            name: "x".repeat(maximum_name_length),
            file_type: FileType::RegularFile,
            node_info: None,
        };
        let payload = encode_directory_entries(core::slice::from_ref(&maximum_entry)).unwrap();
        assert_eq!(payload.len(), MAX_FILE_TRANSFER_SIZE as usize);
        assert_eq!(decode_directory_entries(&payload).unwrap(), [maximum_entry]);

        let oversized_entry = FileDirectoryEntry {
            name: "x".repeat(maximum_name_length + 1),
            file_type: FileType::RegularFile,
            node_info: None,
        };
        assert_eq!(
            encode_directory_entries(&[oversized_entry]),
            Err(DirectoryPayloadError::TooLarge)
        );

        let mut oversized_payload = payload;
        oversized_payload.push(0);
        assert_eq!(
            decode_directory_entries(&oversized_payload),
            Err(DirectoryPayloadError::TooLarge)
        );
    }
}
