// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker mount requests and the values they carry in shared buffers.
//!
//! Mount requests change, or describe, the mount tree of the mount namespace of the file-system
//! context their [`PathStart`] names. Their paths resolve as other path requests' do. A mount
//! request's shared buffer holds its target path, followed by an encoded [`MountSource`]; a mount
//! query's buffer receives an encoded [`MountInfo`].

use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

use crate::ObjectHandle;
use crate::fs::{FileMode, FileUser, PathStart};
use crate::shared_buffer::SharedBufferSequence;

/// The type, source and options a mount was made with, which the broker records without
/// interpreting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountInfo {
    /// The file-system type, such as `tmpfs`.
    pub fs_type: String,
    /// The source, such as a device or the bound path.
    pub source: String,
    /// The options.
    pub options: String,
}

impl MountInfo {
    /// Appends this info's encoding: the type's and the source's lengths as little-endian `u32`s,
    /// then the type, the source and the options.
    fn encode_into(&self, output: &mut Vec<u8>) -> Option<()> {
        for field in [&self.fs_type, &self.source] {
            output.extend_from_slice(&u32::try_from(field.len()).ok()?.to_le_bytes());
        }
        for field in [&self.fs_type, &self.source, &self.options] {
            output.extend_from_slice(field.as_bytes());
        }
        Some(())
    }

    /// Encodes this info for a shared buffer, or returns `None` if a field is too long.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut output = Vec::new();
        self.encode_into(&mut output)?;
        Some(output)
    }

    /// Decodes an info produced by [`Self::encode`].
    pub fn decode(mut encoded: &[u8]) -> Result<Self, MountCodecError> {
        let fs_type_length = take_length(&mut encoded)?;
        let source_length = take_length(&mut encoded)?;
        let fs_type = take_string(&mut encoded, fs_type_length)?;
        let source = take_string(&mut encoded, source_length)?;
        let rest = encoded.len();
        let options = take_string(&mut encoded, rest)?;
        Ok(Self {
            fs_type,
            source,
            options,
        })
    }
}

/// What a new mount shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountSource {
    /// A new, empty in-memory file system.
    NewTmpfs {
        /// Permission bits of its root directory.
        mode: FileMode,
        /// Owner of its root directory.
        owner: FileUser,
        /// What the mount records.
        info: MountInfo,
        /// Whether writes through the mount fail.
        read_only: bool,
    },
    /// The node `path` names, resolved in the request's context, relative paths from `base` if
    /// given; the mount copies its source mount's info and read-only flag.
    Bind {
        /// An open file, of the caller, that a relative `path` starts from, or that the mount
        /// shows itself if `path` is empty.
        base: Option<ObjectHandle>,
        /// The path.
        path: String,
        /// Whether the mounts attached at or below the node are copied onto the new mount too.
        recursive: bool,
    },
}

const SOURCE_TAG_NEW_TMPFS: u8 = 0;
const SOURCE_TAG_BIND: u8 = 1;

impl MountSource {
    /// Encodes this source for a shared buffer, or returns `None` if a string is too long.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        let mut output = Vec::new();
        match self {
            Self::NewTmpfs {
                mode,
                owner,
                info,
                read_only,
            } => {
                output.push(SOURCE_TAG_NEW_TMPFS);
                output.extend_from_slice(&mode.bits().to_le_bytes());
                output.extend_from_slice(&owner.user.to_le_bytes());
                output.extend_from_slice(&owner.group.to_le_bytes());
                output.push(u8::from(*read_only));
                info.encode_into(&mut output)?;
            }
            Self::Bind {
                base,
                path,
                recursive,
            } => {
                output.push(SOURCE_TAG_BIND);
                match base {
                    Some(handle) => {
                        output.push(1);
                        output.extend_from_slice(&handle.0.to_le_bytes());
                    }
                    None => output.push(0),
                }
                output.push(u8::from(*recursive));
                output.extend_from_slice(path.as_bytes());
            }
        }
        Some(output)
    }

    /// Decodes a source produced by [`Self::encode`].
    pub fn decode(mut encoded: &[u8]) -> Result<Self, MountCodecError> {
        match take_u8(&mut encoded)? {
            SOURCE_TAG_NEW_TMPFS => {
                let mode = FileMode::from_bits(u16::from_le_bytes(take(&mut encoded)?))
                    .ok_or(MountCodecError::Invalid)?;
                let owner = FileUser {
                    user: u16::from_le_bytes(take(&mut encoded)?),
                    group: u16::from_le_bytes(take(&mut encoded)?),
                };
                let read_only = take_bool(&mut encoded)?;
                Ok(Self::NewTmpfs {
                    mode,
                    owner,
                    info: MountInfo::decode(encoded)?,
                    read_only,
                })
            }
            SOURCE_TAG_BIND => {
                let base = match take_u8(&mut encoded)? {
                    0 => None,
                    1 => Some(ObjectHandle(u64::from_le_bytes(take(&mut encoded)?))),
                    _ => return Err(MountCodecError::Invalid),
                };
                let recursive = take_bool(&mut encoded)?;
                let rest = encoded.len();
                let path = take_string(&mut encoded, rest)?;
                Ok(Self::Bind {
                    base,
                    path,
                    recursive,
                })
            }
            _ => Err(MountCodecError::Invalid),
        }
    }
}

/// Failure to decode a mount value from a shared buffer.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MountCodecError {
    #[error("truncated mount value")]
    Truncated,
    #[error("invalid mount value")]
    Invalid,
}

fn take<const N: usize>(encoded: &mut &[u8]) -> Result<[u8; N], MountCodecError> {
    let (bytes, rest) = encoded
        .split_first_chunk::<N>()
        .ok_or(MountCodecError::Truncated)?;
    *encoded = rest;
    Ok(*bytes)
}

fn take_u8(encoded: &mut &[u8]) -> Result<u8, MountCodecError> {
    Ok(take::<1>(encoded)?[0])
}

fn take_bool(encoded: &mut &[u8]) -> Result<bool, MountCodecError> {
    match take_u8(encoded)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(MountCodecError::Invalid),
    }
}

fn take_length(encoded: &mut &[u8]) -> Result<usize, MountCodecError> {
    usize::try_from(u32::from_le_bytes(take(encoded)?)).map_err(|_| MountCodecError::Invalid)
}

fn take_string(encoded: &mut &[u8], length: usize) -> Result<String, MountCodecError> {
    let (bytes, rest) = encoded
        .split_at_checked(length)
        .ok_or(MountCodecError::Truncated)?;
    *encoded = rest;
    core::str::from_utf8(bytes)
        .map(String::from)
        .map_err(|_| MountCodecError::Invalid)
}

/// The mount a node is on, as a mount query reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeMount {
    /// What the mount records.
    pub info: MountInfo,
    /// Whether writes through the mount fail.
    pub read_only: bool,
    /// Whether the node is the mount's root.
    pub at_root: bool,
    /// Whether the mount is in the mount namespace of the query's context, rather than another
    /// namespace's or detached.
    pub in_namespace: bool,
}

/// Mounts a new file system, or a bind of a node, on the node a path names, on top of any mounts
/// already stacked there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountRequest {
    /// Shared-buffer region holding the UTF-8 target path, followed by an encoded
    /// [`MountSource`].
    pub buffer: SharedBufferSequence,
    /// Length of the target path at the start of `buffer`.
    pub path_length: u32,
    /// Where the target path starts; its context's mount namespace is the one changed.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Makes writes through the mount whose root a path names fail, or succeed again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetReadOnlyRequest {
    /// Shared-buffer region containing one UTF-8 path, which may be empty to name the start's
    /// base itself.
    pub path: SharedBufferSequence,
    /// Where the path starts.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// Whether the mount becomes read-only.
    pub read_only: bool,
}

/// Unmounts the topmost mount stacked on the node a path names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnmountRequest {
    /// Shared-buffer region containing one UTF-8 path, which may be empty to name the start's
    /// base itself.
    pub path: SharedBufferSequence,
    /// Where the path starts.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// Whether the mounts attached under it are detached with it, each a tree of its own, even
    /// while busy.
    pub detach: bool,
    /// Whether a final symbolic link is followed.
    pub follow_final: bool,
}

/// Makes a directory, a mount's root, the root of the mount namespace in place of the caller's
/// root mount, which moves to another directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PivotRootRequest {
    /// Shared-buffer region containing the UTF-8 new root's path followed by the path of where
    /// the old root mount goes.
    pub paths: SharedBufferSequence,
    /// Length of the new root's path at the start of `paths`.
    pub new_root_length: u32,
    /// Where both paths start.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Makes a directory the root of a file-system context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChangeRootRequest {
    /// Shared-buffer region containing one UTF-8 path, which may be empty to name the start's
    /// base itself.
    pub path: SharedBufferSequence,
    /// Where the path starts; its context's root changes.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
}

/// Reads the mount a node is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountInfoRequest {
    /// Shared-buffer region whose first `path_length` bytes hold one UTF-8 path, which may be
    /// empty to name the start's base itself; the broker replaces its contents with the mount's
    /// encoded [`MountInfo`].
    pub buffer: SharedBufferSequence,
    /// Length of the path at the start of `buffer`.
    pub path_length: u32,
    /// Where the path starts; membership is in its context's namespace.
    pub start: PathStart,
    /// Caller identity for permission checks.
    pub user: FileUser,
    /// Whether a final symbolic link is followed.
    pub follow_final: bool,
}

/// Successful mount query response, whose info the broker wrote to the request's buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountInfoResponse {
    /// Length of the encoded [`MountInfo`] at the start of the request buffer.
    pub length: u32,
    /// Whether writes through the mount fail.
    pub read_only: bool,
    /// Whether the node is the mount's root.
    pub at_root: bool,
    /// Whether the mount is in the mount namespace of the request's context.
    pub in_namespace: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> MountInfo {
        MountInfo {
            fs_type: "tmpfs".into(),
            source: "none".into(),
            options: "rw,size=1m".into(),
        }
    }

    #[test]
    fn mount_values_round_trip() {
        assert_eq!(MountInfo::decode(&info().encode().unwrap()), Ok(info()));
        assert_eq!(
            MountInfo::decode(&MountInfo::default().encode().unwrap()),
            Ok(MountInfo::default())
        );
        for source in [
            MountSource::NewTmpfs {
                mode: FileMode::from_bits(0o1777).unwrap(),
                owner: FileUser {
                    user: 1000,
                    group: u16::MAX,
                },
                info: info(),
                read_only: true,
            },
            MountSource::Bind {
                base: Some(ObjectHandle(u64::MAX)),
                path: "relative/dir".into(),
                recursive: true,
            },
            MountSource::Bind {
                base: None,
                path: String::new(),
                recursive: false,
            },
        ] {
            assert_eq!(MountSource::decode(&source.encode().unwrap()), Ok(source));
        }
    }

    #[test]
    fn mount_values_decode_strictly() {
        let encoded = info().encode().unwrap();
        for length in 0..8 {
            assert_eq!(
                MountInfo::decode(&encoded[..length]),
                Err(MountCodecError::Truncated)
            );
        }
        // The type's length runs past the end.
        let mut long_type = encoded.clone();
        long_type[0] = 0xff;
        assert_eq!(
            MountInfo::decode(&long_type),
            Err(MountCodecError::Truncated)
        );
        let mut invalid_utf8 = encoded;
        invalid_utf8[8] = 0xff;
        assert_eq!(
            MountInfo::decode(&invalid_utf8),
            Err(MountCodecError::Invalid)
        );

        let bind = MountSource::Bind {
            base: None,
            path: "dir".into(),
            recursive: true,
        }
        .encode()
        .unwrap();
        // The tag, the base's presence and the recursive flag.
        for (index, value) in [(0, 2), (1, 2), (2, 2)] {
            let mut invalid = bind.clone();
            invalid[index] = value;
            assert_eq!(MountSource::decode(&invalid), Err(MountCodecError::Invalid));
        }
        assert_eq!(MountSource::decode(&[]), Err(MountCodecError::Truncated));
        let tmpfs = MountSource::NewTmpfs {
            mode: FileMode::empty(),
            owner: FileUser::ROOT,
            info: MountInfo::default(),
            read_only: false,
        }
        .encode()
        .unwrap();
        let mut unsupported_mode = tmpfs.clone();
        unsupported_mode[1..3].copy_from_slice(&0o10000u16.to_le_bytes());
        assert_eq!(
            MountSource::decode(&unsupported_mode),
            Err(MountCodecError::Invalid)
        );
        let mut invalid_read_only = tmpfs;
        invalid_read_only[7] = 2;
        assert_eq!(
            MountSource::decode(&invalid_read_only),
            Err(MountCodecError::Invalid)
        );
    }
}
