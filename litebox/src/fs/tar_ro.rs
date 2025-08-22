//! A read-only tar-backed file system.
//!
//! ```txt
//!                  __
//!                 / /
//!                / /
//!               / /
//!     ================
//!     |       / /    |
//!     |______/_/_____|
//!     \              /
//!      |            |
//!      |            |
//!      \            /
//!       |          |
//!       |  O  O  O |
//!        \O O O O /
//!        | O O O O|
//!        |________|
//!
//! Taro Milk Tea, Tapioca Bubbles, 50% Sugar, No Ice.
//! ```

use alloc::borrow::ToOwned as _;
use alloc::string::String;
use alloc::vec::Vec;
use hashbrown::HashMap;
use tar_no_std::TarArchive;

use crate::{
    LiteBox,
    fs::{DirEntry, FileType},
    path::Arg as _,
    sync,
    utilities::anymap::AnyMap,
};

use super::{
    Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
    errors::{
        ChmodError, ChownError, CloseError, MkdirError, OpenError, PathError, ReadDirError,
        ReadError, RmdirError, SeekError, UnlinkError, WriteError,
    },
};

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'Taro'.hex()`.
const DEVICE_ID: usize = 0x5461726f;

/// TODO(jayb): Replace this proper auto-incrementing inode number storage (although that will
/// require migrating to the hashmap based tar entry storage). This is ok for now, until something
/// is actually checking for real inode numbers.
const TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER: usize = 0xFACE;

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all files in-memory, via
/// a read-only `.tar` file.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    tar_data: TarArchive,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

/// An empty tar file to support an empty file system.
pub fn empty_tar_file() -> Vec<u8> {
    alloc::vec![0u8; 10240]
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance from provided `tar_data`.
    ///
    /// Note: this function takes `tar_data` as a `Vec` rather than a `&[u8]` to eliminate a memcpy
    /// and ensure that full ownership is taken; if the fact that it is a `Vec` is sub-optimal due
    /// to an _external_ forced-memcpy for any particular use case, then this could be updated to a
    /// more flexible type, at the cost of adding an additional lifetime throughout this file
    /// system.
    ///
    /// Use [`empty_tar_file`] if you need an empty file system.
    ///
    /// # Panics
    ///
    /// Panics if the provided `tar_data` is found to be an invalid `.tar` file.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, tar_data: Vec<u8>) -> Self {
        Self {
            litebox: litebox.clone(),
            tar_data: TarArchive::new(tar_data.into_boxed_slice()).unwrap(),
            current_working_dir: "/".into(),
        }
    }

    /// Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    /// for any relative paths from current working directory.
    ///
    /// Note: does NOT account for symlinks.
    fn absolute_path(&self, path: impl crate::path::Arg) -> Result<String, PathError> {
        assert!(self.current_working_dir.ends_with('/'));
        let path = path.as_rust_str()?;
        if path.starts_with('/') {
            // Absolute path
            Ok(path.normalized()?)
        } else {
            // Relative path
            Ok((self.current_working_dir.clone() + path.as_rust_str()?).normalized()?)
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

fn contains_dir(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    assert!(!needle.ends_with('/'));
    haystack.starts_with(needle) && haystack.as_bytes().get(needle.len()) == Some(&b'/')
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        flags: OFlags,
        _mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags = OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!()
        }
        let path = self.absolute_path(path)?;
        if path.is_empty() {
            // We are at the root directory, we should just return early.
            return Ok(self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                path: path.clone(),
                metadata: AnyMap::new(),
            }));
        }
        assert!(path.starts_with('/'));
        let path = &path[1..];
        let Some((idx, entry)) =
            // TODO: this might be slow for large tar files, due to a linear scan. If better perf is
            // needed, we can add a hashmap layer after doing one scan (in `new()`) that allows a
            // direct hashmap lookup of relevant information and data.
            self.tar_data.entries().enumerate().find(|(_, entry)| {
                match entry.filename().as_str() {
                    Ok(p) => p == path || contains_dir(p, path),
                    Err(_) => false,
                }
            })
        else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if flags.contains(OFlags::RDWR) || flags.contains(OFlags::WRONLY) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        assert!(flags.contains(OFlags::RDONLY));
        if entry.filename().as_str().unwrap() == path {
            // it is a file
            if flags.contains(OFlags::DIRECTORY) {
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
            Ok(self
                .litebox
                .descriptor_table_mut()
                .insert(Descriptor::File {
                    idx,
                    position: 0,
                    metadata: AnyMap::new(),
                }))
        } else {
            // it is a dir
            Ok(self.litebox.descriptor_table_mut().insert(Descriptor::Dir {
                path: path.to_owned(),
                metadata: AnyMap::new(),
            }))
        }
    }

    fn close(&self, fd: FileFd<Platform>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        mut offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            idx,
            position,
            metadata: _,
        } = &mut descriptor_table.get_entry_mut(fd).entry
        else {
            return Err(ReadError::NotAFile);
        };
        let position = offset.as_mut().unwrap_or(position);
        let file = self.tar_data.entries().nth(*idx).unwrap().data();
        let start = (*position).min(file.len());
        let end = position.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        _buf: &[u8],
        _offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        match self.litebox.descriptor_table().get_entry(fd).entry {
            Descriptor::File { .. } => Err(WriteError::NotForWriting),
            Descriptor::Dir { .. } => Err(WriteError::NotAFile),
        }
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            idx,
            position,
            metadata: _,
        } = &mut descriptor_table.get_entry_mut(fd).entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = self.tar_data.entries().nth(*idx).unwrap().data().len();
        let base = match whence {
            SeekWhence::RelativeToBeginning => 0,
            SeekWhence::RelativeToCurrentOffset => *position,
            SeekWhence::RelativeToEnd => file_len,
        };
        let new_posn = base
            .checked_add_signed(offset)
            .ok_or(SeekError::InvalidOffset)?;
        if new_posn > file_len {
            Err(SeekError::InvalidOffset)
        } else {
            *position = new_posn;
            Ok(new_posn)
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, _mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self
            .tar_data
            .entries()
            .any(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            })
        {
            Err(ChmodError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self
            .tar_data
            .entries()
            .any(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            })
        {
            Err(ChownError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        let entry = self
            .tar_data
            .entries()
            .find(|entry| match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            });
        match entry {
            None => Err(PathError::NoSuchFileOrDirectory)?,
            Some(p) if p.filename().as_str().unwrap() != path => Err(UnlinkError::IsADirectory),
            Some(_) => Err(UnlinkError::ReadOnlyFileSystem),
        }
    }

    fn mkdir(&self, _path: impl crate::path::Arg, _mode: Mode) -> Result<(), MkdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn rmdir(&self, _path: impl crate::path::Arg) -> Result<(), RmdirError> {
        // TODO: Do we need to do the type of checks that are happening in the other functions, or
        // should the other functions be simplified to this?
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { path, metadata: _ } = &descriptor_table.get_entry(fd).entry else {
            return Err(ReadDirError::NotADirectory);
        };
        // Store into a hashmap to collapse together the entries we end up with for multiple files
        // within a sub-dir.
        let entries: HashMap<String, (FileType, usize)> = self
            .tar_data
            .entries()
            .enumerate()
            .map(|(idx, entry)| (idx, entry.filename()))
            .filter_map(|(idx, p)| {
                let p = p.as_str().ok()?;
                contains_dir(p, path).then(|| {
                    // Drop the directory path from `p`
                    let suffix = p.trim_start_matches(path).trim_start_matches('/');
                    // Then drop everything after the first `/`; if there is any then it was a dir,
                    // otherwise it was a file.
                    match suffix.split_once('/') {
                        Some((dir, _)) => (
                            String::from(dir),
                            (FileType::Directory, TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER),
                        ),
                        None => (String::from(suffix), (FileType::RegularFile, idx + 1)), // ino starts at 1 (zero represents deleted file)
                    }
                })
            })
            .collect();

        // Add "." and ".." entries first.
        // In this read-only tar FS we don't maintain distinct inode numbers per-dir,
        // so use the same directory inode constant for directories (including root).
        let mut out: Vec<DirEntry> = Vec::new();

        out.push(DirEntry {
            name: ".".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.push(DirEntry {
            name: "..".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            }),
        });

        out.extend(
            entries
                .into_iter()
                .map(|(name, (file_type, ino))| DirEntry {
                    name,
                    file_type,
                    ino_info: Some(NodeInfo {
                        dev: DEVICE_ID,
                        ino,
                        rdev: None,
                    }),
                }),
        );
        Ok(out)
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let path = self.absolute_path(path)?;
        let path = &path[1..];
        let entry = self.tar_data.entries().enumerate().find(|(_, entry)| {
            match entry.filename().as_str() {
                Ok(p) => p == path || contains_dir(p, path),
                Err(_) => false,
            }
        });
        match entry {
            None => Err(PathError::NoSuchFileOrDirectory)?,
            Some((_, p)) if p.filename().as_str().unwrap() != path => Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: owner_from_posix_header(p.posix_header()),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
            Some((idx, p)) => Ok(super::FileStatus {
                file_type: super::FileType::RegularFile,
                mode: mode_of_modeflags(p.posix_header().mode.to_flags().unwrap()),
                size: p.size(),
                owner: owner_from_posix_header(p.posix_header()),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    // ino starts at 1 (zero represents deleted file)
                    ino: idx + 1,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
        }
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match &self.litebox.descriptor_table().get_entry(fd).entry {
            Descriptor::File { idx, .. } => {
                let entry = self.tar_data.entries().nth(*idx).unwrap();
                Ok(super::FileStatus {
                    file_type: super::FileType::RegularFile,
                    mode: mode_of_modeflags(entry.posix_header().mode.to_flags().unwrap()),
                    size: entry.size(),
                    owner: owner_from_posix_header(entry.posix_header()),
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        // ino starts at 1 (zero represents deleted file)
                        ino: *idx + 1,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
            }
            Descriptor::Dir { .. } => Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: DEFAULT_DIRECTORY_OWNER,
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            }),
        }
    }

    fn with_metadata<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        match &self.litebox.descriptor_table().get_entry(fd).entry {
            Descriptor::File { metadata, .. } | Descriptor::Dir { metadata, .. } => Ok(f(metadata
                .get::<T>()
                .ok_or(super::errors::MetadataError::NoSuchMetadata)?)),
        }
    }

    fn with_metadata_mut<T: core::any::Any, R>(
        &self,
        fd: &FileFd<Platform>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, super::errors::MetadataError> {
        match &mut self.litebox.descriptor_table().get_entry_mut(fd).entry {
            Descriptor::File { metadata, .. } | Descriptor::Dir { metadata, .. } => Ok(f(metadata
                .get_mut::<T>()
                .ok_or(super::errors::MetadataError::NoSuchMetadata)?)),
        }
    }

    fn set_file_metadata<T: core::any::Any>(
        &self,
        _fd: &FileFd<Platform>,
        metadata: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        Err(super::errors::SetMetadataError::ReadOnlyFileSystem(
            metadata,
        ))
    }

    fn set_fd_metadata<T: core::any::Any>(
        &self,
        fd: &FileFd<Platform>,
        m: T,
    ) -> Result<Option<T>, super::errors::SetMetadataError<T>> {
        match &mut self.litebox.descriptor_table().get_entry_mut(fd).entry {
            Descriptor::File { metadata, .. } | Descriptor::Dir { metadata, .. } => {
                Ok(metadata.insert(m))
            }
        }
    }
}

const DEFAULT_DIR_MODE: Mode =
    Mode::from_bits(Mode::RWXU.bits() | Mode::RWXG.bits() | Mode::RWXO.bits()).unwrap();

const DEFAULT_DIRECTORY_OWNER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

fn mode_of_modeflags(perms: tar_no_std::ModeFlags) -> Mode {
    use tar_no_std::ModeFlags;
    let mut mode = Mode::empty();
    mode.set(Mode::RUSR, perms.contains(ModeFlags::OwnerRead));
    mode.set(Mode::WUSR, perms.contains(ModeFlags::OwnerWrite));
    mode.set(Mode::XUSR, perms.contains(ModeFlags::OwnerExec));
    mode.set(Mode::RGRP, perms.contains(ModeFlags::GroupRead));
    mode.set(Mode::WGRP, perms.contains(ModeFlags::GroupWrite));
    mode.set(Mode::XGRP, perms.contains(ModeFlags::GroupExec));
    mode.set(Mode::ROTH, perms.contains(ModeFlags::OthersRead));
    mode.set(Mode::WOTH, perms.contains(ModeFlags::OthersWrite));
    mode.set(Mode::XOTH, perms.contains(ModeFlags::OthersExec));
    mode
}

fn owner_from_posix_header(posix_header: &tar_no_std::PosixHeader) -> UserInfo {
    UserInfo {
        user: posix_header.uid.as_number().unwrap(),
        group: posix_header.gid.as_number().unwrap(),
    }
}

enum Descriptor {
    File {
        idx: usize,
        position: usize,
        metadata: AnyMap,
    },
    Dir {
        path: String,
        metadata: AnyMap,
    },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    Descriptor;
    -> FileFd<Platform>;
}
