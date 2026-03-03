// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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

use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;
use hashbrown::HashMap;

use crate::{
    LiteBox,
    fs::{DirEntry, FileType},
    path::Arg as _,
    sync,
};

use super::{
    Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
    errors::{
        ChmodError, ChownError, CloseError, MkdirError, OpenError, PathError, ReadDirError,
        ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
    },
};

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'Taro'.hex()`.
const DEVICE_ID: usize = 0x5461726f;

/// TODO(jayb): Replace this proper auto-incrementing inode number storage (although that will
/// currently only applies to directories and can be revisited when/if something is actually
/// checking for directory inodes.
const TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER: usize = 0xFACE;

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all files in-memory, via
/// a read-only `.tar` file.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    tar_index: TarIndex,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
}

/// An empty tar file to support an empty file system.
pub const EMPTY_TAR_FILE: &[u8] = &[0u8; 10240];

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance from provided `tar_data`.
    ///
    /// The filesystem stores the provided bytes and builds an index up-front for O(1) lookups.
    /// Using `Cow` avoids an unnecessary copy while allowing either borrowed or owned input.
    ///
    /// Use [`EMPTY_TAR_FILE`] if you need an empty file system.
    ///
    /// # Panics
    ///
    /// Panics if the provided `tar_data` is found to be an invalid `.tar` file.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, tar_data: alloc::borrow::Cow<'static, [u8]>) -> Self {
        Self {
            litebox: litebox.clone(),
            tar_index: TarIndex::new(tar_data),
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

struct IndexedFile {
    data_range: Range<usize>,
    mode: Mode,
    owner: UserInfo,
    ino: usize,
}

struct IndexedDir {
    owner: Option<UserInfo>,
    children: HashMap<String, (FileType, usize)>,
}

struct TarIndex {
    tar_data: alloc::borrow::Cow<'static, [u8]>,
    files: Vec<IndexedFile>,
    files_by_path: HashMap<String, usize>,
    dirs: Vec<IndexedDir>,
    dirs_by_path: HashMap<String, usize>,
}

impl TarIndex {
    fn new(tar_data: alloc::borrow::Cow<'static, [u8]>) -> Self {
        let archive = tar_no_std::TarArchiveRef::new(tar_data.as_ref()).expect("invalid tar data");
        let base_ptr = tar_data.as_ptr() as usize;

        let mut files = Vec::new();
        let mut files_by_path: HashMap<String, usize> = HashMap::new();
        for (idx, entry) in archive.entries().enumerate() {
            let filename = entry.filename();
            let Ok(path) = filename.as_str() else {
                continue;
            };
            let path = normalize_tar_filename(path);
            assert!(!path.is_empty());

            let data = entry.data();
            let start = (data.as_ptr() as usize).checked_sub(base_ptr).unwrap();
            let end = start.checked_add(data.len()).unwrap();

            let indexed_file = IndexedFile {
                data_range: start..end,
                mode: mode_of_modeflags(entry.posix_header().mode.to_flags().unwrap()),
                owner: owner_from_posix_header(entry.posix_header()),
                // ino starts at 1 (zero represents deleted file)
                ino: idx + 1,
            };

            let file_idx = files.len();
            files.push(indexed_file);
            let old = files_by_path.insert(path.into(), file_idx);
            assert!(
                old.is_none(),
                "tar files with rewritten file contents are unsupported"
            );
        }

        let mut dirs = alloc::vec![IndexedDir {
            owner: None,
            children: HashMap::new(),
        }];
        let mut dirs_by_path: HashMap<String, usize> = [(String::new(), 0)].into_iter().collect();
        for (path, &file_idx) in &files_by_path {
            let file = &files[file_idx];
            let components: Vec<&str> = path
                .split('/')
                .filter(|component| !component.is_empty())
                .collect();

            let mut parent = String::new();
            let mut parent_dir_idx = 0;
            for (component_idx, component) in components.iter().enumerate() {
                let is_last_component = component_idx + 1 == components.len();
                let (file_type, ino) = if is_last_component {
                    (FileType::RegularFile, file.ino)
                } else {
                    (FileType::Directory, TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER)
                };

                dirs[parent_dir_idx].owner.get_or_insert(file.owner);
                dirs[parent_dir_idx]
                    .children
                    .insert((*component).into(), (file_type, ino));

                if is_last_component {
                    break;
                }

                if parent.is_empty() {
                    parent.push_str(component);
                } else {
                    parent.push('/');
                    parent.push_str(component);
                }
                let child_dir_idx = *dirs_by_path.entry(parent.clone()).or_insert_with(|| {
                    dirs.push(IndexedDir {
                        owner: Some(file.owner),
                        children: HashMap::new(),
                    });
                    dirs.len() - 1
                });
                dirs[child_dir_idx].owner.get_or_insert(file.owner);
                parent_dir_idx = child_dir_idx;
            }
        }

        Self {
            tar_data,
            files,
            files_by_path,
            dirs,
            dirs_by_path,
        }
    }

    fn file_data(&self, file_idx: usize) -> &[u8] {
        let range = self.files[file_idx].data_range.clone();
        &self.tar_data[range]
    }

    fn file_by_path(&self, path: &str) -> Option<(usize, &IndexedFile)> {
        let file_idx = *self.files_by_path.get(path)?;
        Some((file_idx, &self.files[file_idx]))
    }

    fn dir_by_path(&self, path: &str) -> Option<(usize, &IndexedDir)> {
        let dir_idx = *self.dirs_by_path.get(path)?;
        Some((dir_idx, &self.dirs[dir_idx]))
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

/// Strip the `./` prefix from tar filenames if present.
///
/// This is helpful for tar files that have been created via `tar cvf foo.tar .`
fn normalize_tar_filename(filename: &str) -> &str {
    filename.strip_prefix("./").unwrap_or(filename)
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
            | OFlags::CREAT
            | OFlags::EXCL
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOFOLLOW
            | OFlags::APPEND;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }
        if flags.contains(OFlags::CREAT) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let path = self.absolute_path(path)?;
        if path.is_empty() {
            // We are at the root directory, we should just return early.
            let (idx, _) = self
                .tar_index
                .dir_by_path("")
                .expect("root directory always exists");
            return Ok(self
                .litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { idx }));
        }
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if flags.contains(OFlags::RDWR) || flags.contains(OFlags::WRONLY) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        assert!(flags.contains(OFlags::RDONLY));
        let fd = if let Some((idx, _)) = self.tar_index.file_by_path(path) {
            if flags.contains(OFlags::DIRECTORY) {
                return Err(OpenError::PathError(PathError::ComponentNotADirectory));
            }
            self.litebox
                .descriptor_table_mut()
                .insert(Descriptor::File { idx, position: 0 })
        } else if let Some((idx, _)) = self.tar_index.dir_by_path(path) {
            self.litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { idx })
        } else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if flags.contains(OFlags::TRUNC) {
            match self.truncate(&fd, 0, true) {
                Ok(()) => {}
                Err(e) => {
                    self.close(&fd).unwrap();
                    return Err(e.into());
                }
            }
        }
        Ok(fd)
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
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
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        else {
            return Err(ReadError::NotAFile);
        };
        let position = offset.as_mut().unwrap_or(position);
        let file = self.tar_index.file_data(*idx);
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
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        {
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
        let Descriptor::File { idx, position } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = self.tar_index.files[*idx].data_range.len();
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

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        _length: usize,
        _reset_offset: bool,
    ) -> Result<(), TruncateError> {
        match self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry
        {
            Descriptor::File { .. } => Err(TruncateError::NotForWriting),
            Descriptor::Dir { .. } => Err(TruncateError::IsDirectory),
        }
    }

    fn chmod(&self, path: impl crate::path::Arg, _mode: Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        assert!(path.starts_with('/'));
        let path = &path[1..];
        if self.tar_index.file_by_path(path).is_some() || self.tar_index.dir_by_path(path).is_some()
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
        if self.tar_index.file_by_path(path).is_some() || self.tar_index.dir_by_path(path).is_some()
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
        if self.tar_index.file_by_path(path).is_some() {
            Err(UnlinkError::ReadOnlyFileSystem)
        } else if self.tar_index.dir_by_path(path).is_some() {
            Err(UnlinkError::IsADirectory)
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
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
        let Descriptor::Dir { idx } = &descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?
            .entry
        else {
            return Err(ReadDirError::NotADirectory);
        };
        let dir = &self.tar_index.dirs[*idx];

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
            dir.children
                .iter()
                .map(|(name, (file_type, ino))| DirEntry {
                    name: name.clone(),
                    file_type: file_type.clone(),
                    ino_info: Some(NodeInfo {
                        dev: DEVICE_ID,
                        ino: *ino,
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
        let path = if path.is_empty() {
            ""
        } else {
            assert!(path.starts_with('/'));
            &path[1..]
        };
        if let Some((_, file)) = self.tar_index.file_by_path(path) {
            Ok(super::FileStatus {
                file_type: super::FileType::RegularFile,
                mode: file.mode,
                size: file.data_range.len(),
                owner: file.owner,
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: file.ino,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            })
        } else if let Some((_, dir)) = self.tar_index.dir_by_path(path) {
            Ok(super::FileStatus {
                file_type: super::FileType::Directory,
                mode: DEFAULT_DIR_MODE,
                size: super::DEFAULT_DIRECTORY_SIZE,
                owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                node_info: NodeInfo {
                    dev: DEVICE_ID,
                    ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                    rdev: None,
                },
                blksize: BLOCK_SIZE,
            })
        } else {
            Err(PathError::NoSuchFileOrDirectory)?
        }
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(super::errors::FileStatusError::ClosedFd)?
            .entry
        {
            Descriptor::File { idx, .. } => {
                let file = &self.tar_index.files[*idx];
                Ok(super::FileStatus {
                    file_type: super::FileType::RegularFile,
                    mode: file.mode,
                    size: file.data_range.len(),
                    owner: file.owner,
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        ino: file.ino,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
            }
            Descriptor::Dir { idx } => {
                let dir = &self.tar_index.dirs[*idx];
                Ok(super::FileStatus {
                    file_type: super::FileType::Directory,
                    mode: DEFAULT_DIR_MODE,
                    size: super::DEFAULT_DIRECTORY_SIZE,
                    owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                    node_info: NodeInfo {
                        dev: DEVICE_ID,
                        ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                        rdev: None,
                    },
                    blksize: BLOCK_SIZE,
                })
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
    File { idx: usize, position: usize },
    Dir { idx: usize },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    Descriptor;
    -> FileFd<Platform>;
}
