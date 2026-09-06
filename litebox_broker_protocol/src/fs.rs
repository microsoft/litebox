// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker filesystem requests, responses, and ABI-neutral values.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use thiserror::Error;

use crate::ObjectHandle;
use crate::shared_buffer::{SHARED_BUFFER_SLOT_SIZE, SharedBufferDescriptor};

/// Maximum bytes transferred through one filesystem shared-buffer request.
pub const MAX_FILESYSTEM_TRANSFER_SIZE: u32 = SHARED_BUFFER_SLOT_SIZE;

/// Broker-owned filesystem namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemNamespace {
    /// Guest-visible filesystem namespace.
    Guest,
    /// Private backing store for Windows registry state.
    WindowsRegistry,
}

/// Filesystem user identity used for permission checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemUser {
    /// Effective user ID.
    pub user: u16,
    /// Effective group ID.
    pub group: u16,
}

/// Filesystem object kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemFileType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Character device.
    CharacterDevice,
}

/// Device and inode identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemNodeInfo {
    /// Device number.
    pub dev: u64,
    /// Inode number.
    pub ino: u64,
    /// Referenced device number for special files.
    pub rdev: Option<u64>,
}

/// Status returned for a filesystem object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FilesystemFileStatus {
    /// Object kind.
    pub file_type: FilesystemFileType,
    /// Permission and mode bits.
    pub mode: u32,
    /// Object size in bytes.
    pub size: u64,
    /// Owner identity.
    pub owner: FilesystemUser,
    /// Device and inode identity.
    pub node_info: FilesystemNodeInfo,
    /// Preferred filesystem I/O block size.
    pub block_size: u64,
}

/// One directory entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemDirectoryEntry {
    /// Entry name.
    pub name: String,
    /// Entry kind.
    pub file_type: FilesystemFileType,
    /// Optional device and inode identity.
    pub node_info: Option<FilesystemNodeInfo>,
}

/// Filesystem operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilesystemError {
    #[error("requested access is not allowed")]
    AccessNotAllowed,
    #[error("parent directory does not allow writes")]
    NoWritePermissions,
    #[error("filesystem is read-only")]
    ReadOnlyFilesystem,
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

impl FilesystemError {
    /// Converts one raw wire value to a filesystem error.
    pub const fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::AccessNotAllowed),
            2 => Some(Self::NoWritePermissions),
            3 => Some(Self::ReadOnlyFilesystem),
            4 => Some(Self::AlreadyExists),
            5 => Some(Self::Io),
            6 => Some(Self::NoSuchFileOrDirectory),
            7 => Some(Self::NoSearchPermissions),
            8 => Some(Self::InvalidPathname),
            9 => Some(Self::MissingComponent),
            10 => Some(Self::ComponentNotDirectory),
            11 => Some(Self::NotFile),
            12 => Some(Self::NotForReading),
            13 => Some(Self::NotForWriting),
            14 => Some(Self::InvalidOffset),
            15 => Some(Self::NonSeekable),
            16 => Some(Self::IsDirectory),
            17 => Some(Self::IsTerminalDevice),
            18 => Some(Self::NotOwner),
            19 => Some(Self::NotDirectory),
            20 => Some(Self::Busy),
            21 => Some(Self::NotEmpty),
            _ => None,
        }
    }

    /// Returns the raw wire value for this filesystem error.
    pub const fn as_raw(self) -> u8 {
        match self {
            Self::AccessNotAllowed => 1,
            Self::NoWritePermissions => 2,
            Self::ReadOnlyFilesystem => 3,
            Self::AlreadyExists => 4,
            Self::Io => 5,
            Self::NoSuchFileOrDirectory => 6,
            Self::NoSearchPermissions => 7,
            Self::InvalidPathname => 8,
            Self::MissingComponent => 9,
            Self::ComponentNotDirectory => 10,
            Self::NotFile => 11,
            Self::NotForReading => 12,
            Self::NotForWriting => 13,
            Self::InvalidOffset => 14,
            Self::NonSeekable => 15,
            Self::IsDirectory => 16,
            Self::IsTerminalDevice => 17,
            Self::NotOwner => 18,
            Self::NotDirectory => 19,
            Self::Busy => 20,
            Self::NotEmpty => 21,
        }
    }
}

/// Seek origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemSeekWhence {
    /// Offset from the beginning of the file.
    Beginning,
    /// Offset from the current open-file-description position.
    Current,
    /// Offset from the end of the file.
    End,
}

/// Opens or creates a filesystem object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
    /// Open flags.
    pub flags: u32,
    /// Creation mode.
    pub mode: u32,
}

/// Successful open response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFileResponse {
    /// Broker-owned open-file-description handle.
    pub handle: ObjectHandle,
}

/// Reads from an open file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadFileRequest {
    /// Open-file-description handle.
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
    /// Open-file-description handle.
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
    /// Open-file-description handle.
    pub handle: ObjectHandle,
    /// Signed offset relative to `whence`.
    pub offset: i64,
    /// Seek origin.
    pub whence: FilesystemSeekWhence,
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
    /// Open-file-description handle.
    pub handle: ObjectHandle,
    /// New file length.
    pub length: u64,
    /// Whether to reset the shared position to zero.
    pub reset_offset: bool,
}

/// Reads all directory entries into a shared-buffer region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadDirectoryRequest {
    /// Open-directory-description handle.
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
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
}

/// Reads status by open handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleFileStatusRequest {
    /// Open-file-description handle.
    pub handle: ObjectHandle,
}

/// Changes mode bits by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChmodFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
    /// New mode bits.
    pub mode: u32,
}

/// Changes ownership by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChownFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub acting_user: FilesystemUser,
    /// New user ID, if changed.
    pub user: Option<u16>,
    /// New group ID, if changed.
    pub group: Option<u16>,
}

/// Removes a file by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlinkFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
}

/// Creates a directory by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MkdirFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
    /// New directory mode.
    pub mode: u32,
}

/// Removes a directory by path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RmdirFileRequest {
    /// Filesystem namespace containing the path.
    pub namespace: FilesystemNamespace,
    /// Shared-buffer region containing one absolute UTF-8 path.
    pub path: SharedBufferDescriptor,
    /// Caller identity for permission checks.
    pub user: FilesystemUser,
}

/// Error while encoding or decoding a shared directory payload.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DirectoryPayloadError {
    #[error("directory payload is malformed")]
    Malformed,
    #[error("directory payload exceeds the representable size")]
    TooLarge,
}

/// Encodes directory entries for transfer through a shared buffer.
pub fn encode_directory_entries(
    entries: &[FilesystemDirectoryEntry],
) -> Result<Vec<u8>, DirectoryPayloadError> {
    let (payload, next_index) = encode_directory_entries_chunk(entries, 0, usize::MAX)?;
    if next_index.is_some() {
        return Err(DirectoryPayloadError::TooLarge);
    }
    Ok(payload)
}

/// Encodes one directory-entry chunk no longer than `maximum_length`.
///
/// `start_index` and the returned continuation index count entries, not bytes.
pub fn encode_directory_entries_chunk(
    entries: &[FilesystemDirectoryEntry],
    start_index: usize,
    maximum_length: usize,
) -> Result<(Vec<u8>, Option<u64>), DirectoryPayloadError> {
    let end_index = directory_entries_chunk_end(entries, start_index, maximum_length)?;
    let mut output = Vec::new();
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

/// Copies one directory-entry page whose encoded form fits in `maximum_length`.
///
/// `start_index` and the returned continuation index count entries, not bytes.
pub fn paginate_directory_entries(
    entries: &[FilesystemDirectoryEntry],
    start_index: usize,
    maximum_length: usize,
) -> Result<(Vec<FilesystemDirectoryEntry>, Option<u64>), DirectoryPayloadError> {
    let end_index = directory_entries_chunk_end(entries, start_index, maximum_length)?;
    let mut page = Vec::new();
    page.try_reserve_exact(end_index - start_index)
        .map_err(|_| DirectoryPayloadError::TooLarge)?;
    page.extend_from_slice(&entries[start_index..end_index]);
    let next_index = if end_index == entries.len() {
        None
    } else {
        Some(u64::try_from(end_index).map_err(|_| DirectoryPayloadError::TooLarge)?)
    };
    Ok((page, next_index))
}

fn directory_entries_chunk_end(
    entries: &[FilesystemDirectoryEntry],
    start_index: usize,
    maximum_length: usize,
) -> Result<usize, DirectoryPayloadError> {
    if start_index > entries.len() || maximum_length < size_of::<u32>() {
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
            break;
        }
        end_index += 1;
    }
    Ok(end_index)
}

/// Decodes directory entries transferred through a shared buffer.
pub fn decode_directory_entries(
    payload: &[u8],
) -> Result<Vec<FilesystemDirectoryEntry>, DirectoryPayloadError> {
    const MINIMUM_ENTRY_LENGTH: usize = size_of::<u32>() + 2;

    let mut decoder = DirectoryPayloadDecoder { payload, offset: 0 };
    let count = decoder.u32()? as usize;
    if count > (decoder.payload.len() - decoder.offset) / MINIMUM_ENTRY_LENGTH {
        return Err(DirectoryPayloadError::Malformed);
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(count)
        .map_err(|_| DirectoryPayloadError::TooLarge)?;
    for _ in 0..count {
        let name_len = decoder.u32()? as usize;
        let name = core::str::from_utf8(decoder.take(name_len)?)
            .map_err(|_| DirectoryPayloadError::Malformed)?
            .to_string();
        let file_type =
            file_type_from_raw(decoder.u8()?).ok_or(DirectoryPayloadError::Malformed)?;
        let node_info = match decoder.u8()? {
            0 => None,
            1 => {
                let dev = decoder.u64()?;
                let ino = decoder.u64()?;
                let rdev = match decoder.u8()? {
                    0 => None,
                    1 => Some(decoder.u64()?),
                    _ => return Err(DirectoryPayloadError::Malformed),
                };
                Some(FilesystemNodeInfo { dev, ino, rdev })
            }
            _ => return Err(DirectoryPayloadError::Malformed),
        };
        entries.push(FilesystemDirectoryEntry {
            name,
            file_type,
            node_info,
        });
    }
    if decoder.offset != payload.len() {
        return Err(DirectoryPayloadError::Malformed);
    }
    Ok(entries)
}

pub(crate) const fn file_type_raw(file_type: FilesystemFileType) -> u8 {
    match file_type {
        FilesystemFileType::RegularFile => 0,
        FilesystemFileType::Directory => 1,
        FilesystemFileType::CharacterDevice => 2,
    }
}

pub(crate) const fn file_type_from_raw(raw: u8) -> Option<FilesystemFileType> {
    match raw {
        0 => Some(FilesystemFileType::RegularFile),
        1 => Some(FilesystemFileType::Directory),
        2 => Some(FilesystemFileType::CharacterDevice),
        _ => None,
    }
}

fn encoded_directory_entry_length(
    entry: &FilesystemDirectoryEntry,
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

fn encode_directory_entry(
    output: &mut Vec<u8>,
    entry: &FilesystemDirectoryEntry,
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
                    output.extend_from_slice(&rdev.to_le_bytes());
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
    fn fs_errors_have_unique_stable_wire_values() {
        let errors = [
            FilesystemError::AccessNotAllowed,
            FilesystemError::NoWritePermissions,
            FilesystemError::ReadOnlyFilesystem,
            FilesystemError::AlreadyExists,
            FilesystemError::Io,
            FilesystemError::NoSuchFileOrDirectory,
            FilesystemError::NoSearchPermissions,
            FilesystemError::InvalidPathname,
            FilesystemError::MissingComponent,
            FilesystemError::ComponentNotDirectory,
            FilesystemError::NotFile,
            FilesystemError::NotForReading,
            FilesystemError::NotForWriting,
            FilesystemError::InvalidOffset,
            FilesystemError::NonSeekable,
            FilesystemError::IsDirectory,
            FilesystemError::IsTerminalDevice,
            FilesystemError::NotOwner,
            FilesystemError::NotDirectory,
            FilesystemError::Busy,
            FilesystemError::NotEmpty,
        ];

        for (index, error) in errors.into_iter().enumerate() {
            let raw = u8::try_from(index + 1).unwrap();
            assert_eq!(error.as_raw(), raw);
            assert_eq!(FilesystemError::from_raw(raw), Some(error));
        }
        assert_eq!(FilesystemError::from_raw(0), None);
        assert_eq!(FilesystemError::from_raw(22), None);
    }

    #[test]
    fn directory_payload_round_trips_all_entry_shapes() {
        let entries = vec![
            FilesystemDirectoryEntry {
                name: ".".into(),
                file_type: FilesystemFileType::Directory,
                node_info: None,
            },
            FilesystemDirectoryEntry {
                name: "regular".into(),
                file_type: FilesystemFileType::RegularFile,
                node_info: Some(FilesystemNodeInfo {
                    dev: 2,
                    ino: 3,
                    rdev: None,
                }),
            },
            FilesystemDirectoryEntry {
                name: "device".into(),
                file_type: FilesystemFileType::CharacterDevice,
                node_info: Some(FilesystemNodeInfo {
                    dev: 5,
                    ino: 7,
                    rdev: Some(11),
                }),
            },
        ];

        let payload = encode_directory_entries(&entries).unwrap();
        assert_eq!(decode_directory_entries(&payload).unwrap(), entries);
    }

    #[test]
    fn directory_payload_chunks_at_entry_boundaries() {
        let entries = vec![
            FilesystemDirectoryEntry {
                name: "first".into(),
                file_type: FilesystemFileType::RegularFile,
                node_info: None,
            },
            FilesystemDirectoryEntry {
                name: "second".into(),
                file_type: FilesystemFileType::Directory,
                node_info: None,
            },
        ];
        let first_length = size_of::<u32>() + encoded_directory_entry_length(&entries[0]).unwrap();
        let (first, next_index) =
            encode_directory_entries_chunk(&entries, 0, first_length).unwrap();
        assert_eq!(decode_directory_entries(&first).unwrap(), entries[..1]);
        assert_eq!(next_index, Some(1));

        let (second, next_index) = encode_directory_entries_chunk(&entries, 1, usize::MAX).unwrap();
        assert_eq!(decode_directory_entries(&second).unwrap(), entries[1..]);
        assert_eq!(next_index, None);
        assert_eq!(
            encode_directory_entries_chunk(&entries, 0, first_length - 1),
            Err(DirectoryPayloadError::TooLarge)
        );
    }

    #[test]
    fn directory_payload_rejects_malformed_data() {
        assert_eq!(
            decode_directory_entries(&u32::MAX.to_le_bytes()),
            Err(DirectoryPayloadError::Malformed)
        );

        let valid = encode_directory_entries(&[FilesystemDirectoryEntry {
            name: "entry".into(),
            file_type: FilesystemFileType::RegularFile,
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
}
