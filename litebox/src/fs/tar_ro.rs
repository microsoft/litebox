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

use crate::fs::{DirEntry, FileType};

use super::{
    Mode, NodeInfo, OFlags, UserInfo,
    backend::{DirHandle, FileHandle, WalkingDirHandle},
    errors::{
        ChmodError, ChownError, MkdirError, OpenError, PathError, ReadDirError, ReadError,
        RmdirError, TruncateError, UnlinkError, WalkError, WriteError,
    },
    inode_allocator::InodeAllocator,
};

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

/// A [`super::backend::Backend`] that stores all files in-memory, via a read-only `.tar` file.
pub struct TarRo {
    tar_index: TarIndex,
}

impl TarRo {
    /// Construct a tar backend using a caller-provided inode allocator.
    #[must_use]
    pub fn new(
        tar_data: alloc::borrow::Cow<'static, [u8]>,
        inode_allocator: InodeAllocator,
    ) -> Self {
        Self {
            tar_index: TarIndex::new(tar_data, inode_allocator),
        }
    }
}

impl super::backend::private::Sealed for TarRo {}

/// Directory handle
#[derive(Clone)]
pub struct TarRoDirHandle {
    idx: usize,
}
/// File handle
#[derive(Clone)]
pub struct TarRoFileHandle {
    idx: usize,
}
impl super::backend::BackendHandles for TarRo {
    type WalkingDirHandle<'a> = TarRoDirHandle;
    type FileHandle = TarRoFileHandle;
    type DirHandle = TarRoDirHandle;
}

impl super::backend::Backend for TarRo {
    fn root(&self) -> WalkingDirHandle<'_> {
        WalkingDirHandle::from_typed::<Self>(TarRoDirHandle { idx: 0 })
    }

    fn walk_directories<'a>(
        &'a self,
        from: WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<super::backend::WalkOutcome<WalkingDirHandle<'a>>, WalkError> {
        let mut current = from.into_typed::<Self>();
        let mut walked_components = Vec::with_capacity(components.len());
        for component in components {
            let child = self.tar_index.dirs[current.idx]
                .children
                .get(*component)
                .ok_or(WalkError::PathError(PathError::NoSuchFileOrDirectory))?;
            let IndexedChild::Dir(child_idx) = *child else {
                return Ok(super::backend::WalkOutcome {
                    components: walked_components,
                    last: WalkingDirHandle::from_typed::<Self>(current),
                    stop_reason: super::backend::WalkStopReason::StoppedAtNonDirectory,
                });
            };

            let child = &self.tar_index.dirs[child_idx];
            walked_components.push(super::backend::WalkedComponent {
                permissions: super::backend::PermissionCheck::ByResolver(
                    super::backend::PermissionInfo {
                        mode: DEFAULT_DIR_MODE,
                        owner: child.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                    },
                ),
            });
            current = TarRoDirHandle { idx: child_idx };
        }
        Ok(super::backend::WalkOutcome {
            components: walked_components,
            last: WalkingDirHandle::from_typed::<Self>(current),
            stop_reason: super::backend::WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: WalkingDirHandle<'_>,
        flags: OFlags,
    ) -> Result<DirHandle, OpenError> {
        if flags.intersects(OFlags::CREAT | OFlags::TRUNC | OFlags::WRONLY | OFlags::RDWR) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<WalkingDirHandle<'a>> {
        Some(WalkingDirHandle::from_typed::<Self>(
            dir.get_typed::<Self>().clone(),
        ))
    }

    fn open_file_at(
        &self,
        dir: WalkingDirHandle<'_>,
        name: &str,
        flags: OFlags,
    ) -> Result<super::backend::Permissioned<FileHandle>, OpenError> {
        let dir = dir.into_typed::<Self>();
        let child = self.tar_index.dirs[dir.idx]
            .children
            .get(name)
            .ok_or(OpenError::PathError(PathError::NoSuchFileOrDirectory))?;
        let IndexedChild::File(file_idx) = *child else {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        };
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        if !(flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL))
            && (flags.contains(OFlags::CREAT)
                || flags.contains(OFlags::TRUNC)
                || flags.contains(OFlags::WRONLY)
                || flags.contains(OFlags::RDWR))
        {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        let file = &self.tar_index.files[file_idx];
        Ok(super::backend::Permissioned {
            item: FileHandle::from_typed::<Self>(TarRoFileHandle { idx: file_idx }),
            permissions: super::backend::PermissionCheck::ByResolver(
                super::backend::PermissionInfo {
                    mode: file.mode,
                    owner: file.owner,
                },
            ),
        })
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        Ok(self.tar_index.dirs[handle.idx]
            .children
            .iter()
            .map(|(name, child)| {
                let (file_type, node_info) = match *child {
                    IndexedChild::File(idx) => (
                        FileType::RegularFile,
                        self.tar_index.files[idx].node_info.clone(),
                    ),
                    IndexedChild::Dir(idx) => (
                        FileType::Directory,
                        self.tar_index.dirs[idx].node_info.clone(),
                    ),
                };
                DirEntry {
                    name: name.clone(),
                    file_type,
                    ino_info: Some(node_info),
                }
            })
            .collect())
    }

    fn read(&self, h: &FileHandle, buf: &mut [u8], offset: usize) -> Result<usize, ReadError> {
        let file = self.tar_index.file_data(h.get_typed::<Self>().idx);
        let start = offset.min(file.len());
        let end = offset.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let len = end - start;
        buf[..len].copy_from_slice(&file[start..end]);
        Ok(len)
    }

    fn write(&self, _h: &FileHandle, _buf: &[u8], _offset: usize) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> super::backend::SeekBehavior {
        super::backend::SeekBehavior::PositionBased
    }

    fn file_status(
        &self,
        h: &FileHandle,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let file = &self.tar_index.files[h.get_typed::<Self>().idx];
        Ok(super::FileStatus {
            file_type: FileType::RegularFile,
            mode: file.mode,
            size: file.data_range.len(),
            owner: file.owner,
            node_info: file.node_info.clone(),
            blksize: BLOCK_SIZE,
        })
    }

    fn dir_status(
        &self,
        h: &DirHandle,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let dir = &self.tar_index.dirs[h.get_typed::<Self>().idx];
        Ok(super::FileStatus {
            file_type: FileType::Directory,
            mode: DEFAULT_DIR_MODE,
            size: super::DEFAULT_DIRECTORY_SIZE,
            owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
            node_info: dir.node_info.clone(),
            blksize: BLOCK_SIZE,
        })
    }

    fn create_file_at(
        &self,
        _dir: DirHandle,
        _name: &str,
        _mode: Mode,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn mkdir_at(&self, _dir: DirHandle, _name: &str, _mode: Mode) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, dir: DirHandle, name: &str) -> Result<(), UnlinkError> {
        let dir = dir.into_typed::<Self>();
        match self.tar_index.dirs[dir.idx].children.get(name) {
            Some(IndexedChild::Dir(_)) => Err(UnlinkError::IsADirectory),
            Some(IndexedChild::File(_)) => Err(UnlinkError::ReadOnlyFileSystem),
            None => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    fn rmdir_at(&self, dir: DirHandle, name: &str) -> Result<(), RmdirError> {
        let dir = dir.into_typed::<Self>();
        match self.tar_index.dirs[dir.idx].children.get(name) {
            Some(IndexedChild::Dir(_)) => Err(RmdirError::ReadOnlyFileSystem),
            Some(IndexedChild::File(_)) => Err(RmdirError::NotADirectory),
            None => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    fn chmod_at(&self, dir: DirHandle, name: &str, _mode: Mode) -> Result<(), ChmodError> {
        let dir = dir.into_typed::<Self>();
        if self.tar_index.dirs[dir.idx].children.contains_key(name) {
            Err(ChmodError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory.into())
        }
    }

    fn chown_at(
        &self,
        dir: DirHandle,
        name: &str,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        let dir = dir.into_typed::<Self>();
        if self.tar_index.dirs[dir.idx].children.contains_key(name) {
            Err(ChownError::ReadOnlyFileSystem)
        } else {
            Err(PathError::NoSuchFileOrDirectory.into())
        }
    }
}

/// An empty tar file to support an empty file system.
pub const EMPTY_TAR_FILE: &[u8] = &[0u8; 10240];

struct IndexedFile {
    data_range: Range<usize>,
    mode: Mode,
    owner: UserInfo,
    node_info: NodeInfo,
}

struct IndexedDir {
    owner: Option<UserInfo>,
    node_info: NodeInfo,
    children: HashMap<String, IndexedChild>,
}

#[derive(Clone, Copy)]
enum IndexedChild {
    File(usize),
    Dir(usize),
}

struct TarIndex {
    tar_data: alloc::borrow::Cow<'static, [u8]>,
    files: Vec<IndexedFile>,
    dirs: Vec<IndexedDir>,
}

impl TarIndex {
    fn new(tar_data: alloc::borrow::Cow<'static, [u8]>, inode_allocator: InodeAllocator) -> Self {
        let archive = tar_no_std::TarArchiveRef::new(tar_data.as_ref()).expect("invalid tar data");
        let base_ptr = tar_data.as_ptr() as usize;

        let mut files = Vec::new();
        let mut files_by_path: HashMap<String, usize> = HashMap::new();
        for entry in archive.entries() {
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
                node_info: inode_allocator.next(),
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
            node_info: inode_allocator.next(),
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
                dirs[parent_dir_idx].owner.get_or_insert(file.owner);

                if is_last_component {
                    dirs[parent_dir_idx]
                        .children
                        .insert((*component).into(), IndexedChild::File(file_idx));
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
                        node_info: inode_allocator.next(),
                        children: HashMap::new(),
                    });
                    dirs.len() - 1
                });
                dirs[parent_dir_idx]
                    .children
                    .insert((*component).into(), IndexedChild::Dir(child_dir_idx));
                dirs[child_dir_idx].owner.get_or_insert(file.owner);
                parent_dir_idx = child_dir_idx;
            }
        }

        Self {
            tar_data,
            files,
            dirs,
        }
    }

    fn file_data(&self, file_idx: usize) -> &[u8] {
        let range = self.files[file_idx].data_range.clone();
        &self.tar_data[range]
    }
}

/// Strip the `./` prefix from tar filenames if present.
///
/// This is helpful for tar files that have been created via `tar cvf foo.tar .`
fn normalize_tar_filename(filename: &str) -> &str {
    filename.strip_prefix("./").unwrap_or(filename)
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
