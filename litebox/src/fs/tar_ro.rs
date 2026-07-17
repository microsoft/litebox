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
    sync,
};

use super::{
    Mode, NodeInfo, OFlags, SeekWhence, UserInfo,
    backend::{DirHandle, FileHandle, WalkingDirHandle},
    errors::{
        ChmodError, ChownError, CloseError, MkdirError, OpenError, PathError, ReadDirError,
        ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError, WriteError,
    },
    inode_allocator::InodeAllocator,
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

    fn owned_dir_at(&self, dir: WalkingDirHandle<'_>) -> DirHandle {
        DirHandle::from_typed::<Self>(dir.into_typed::<Self>())
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
                let (file_type, ino) = match *child {
                    IndexedChild::File(idx) => {
                        (FileType::RegularFile, self.tar_index.files[idx].ino)
                    }
                    IndexedChild::Dir(_) => {
                        (FileType::Directory, TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER)
                    }
                };
                DirEntry {
                    name: name.clone(),
                    file_type,
                    ino_info: Some(NodeInfo {
                        dev: DEVICE_ID,
                        ino,
                        rdev: None,
                    }),
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
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: file.ino,
                rdev: None,
            },
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
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: TEMPORARY_DEFAULT_CONSTANT_INODE_NUMBER,
                rdev: None,
            },
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

/// A backing implementation for [`FileSystem`](super::FileSystem), storing all files in-memory, via
/// a read-only `.tar` file.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    resolver: super::resolver::Resolver<Platform, TarRo>,
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
            resolver: super::resolver::Resolver::new(
                litebox,
                TarRo::new(tar_data, InodeAllocator::standalone()),
            ),
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
    #[expect(
        dead_code,
        reason = "jayb: will be used soon before PR is made, DO NOT COMMIT"
    )]
    inode_allocator: InodeAllocator,
}

impl TarIndex {
    fn new(tar_data: alloc::borrow::Cow<'static, [u8]>, inode_allocator: InodeAllocator) -> Self {
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
            inode_allocator,
        }
    }

    fn file_data(&self, file_idx: usize) -> &[u8] {
        let range = self.files[file_idx].data_range.clone();
        &self.tar_data[range]
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
        mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let fd = super::FileSystem::open(&self.resolver, path, flags, mode)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert(Descriptor { fd }))
    }

    fn close(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
        let Some(descriptor) = self.litebox.descriptor_table_mut().remove(fd) else {
            return Ok(());
        };
        super::FileSystem::close(&self.resolver, &descriptor.entry.fd)
    }

    fn read(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::read(&self.resolver, &descriptor.entry.fd, buf, offset)
        })
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(WriteError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::write(&self.resolver, &descriptor.entry.fd, buf, offset)
        })
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(SeekError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::seek(&self.resolver, &descriptor.entry.fd, offset, whence)
        })
    }

    fn truncate(
        &self,
        fd: &FileFd<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(TruncateError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::truncate(&self.resolver, &descriptor.entry.fd, length, reset_offset)
        })
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), ChmodError> {
        super::FileSystem::chmod(&self.resolver, path, mode)
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        super::FileSystem::chown(&self.resolver, path, user, group)
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        super::FileSystem::unlink(&self.resolver, path)
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: Mode) -> Result<(), MkdirError> {
        super::FileSystem::mkdir(&self.resolver, path, mode)
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        super::FileSystem::rmdir(&self.resolver, path)
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::read_dir(&self.resolver, &descriptor.entry.fd)
        })
    }

    fn file_status(
        &self,
        path: impl crate::path::Arg,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        super::FileSystem::file_status(&self.resolver, path)
    }

    fn fd_file_status(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        let descriptor = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(super::errors::FileStatusError::ClosedFd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::fd_file_status(&self.resolver, &descriptor.entry.fd)
        })
    }

    fn get_static_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let descriptor = self.litebox.descriptor_table().entry_handle(fd)?;
        descriptor.with_entry(|descriptor| {
            super::FileSystem::get_static_backing_data(&self.resolver, &descriptor.entry.fd)
        })
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

// TODO(jayb): migrate away from these as soon as the wrapper is cleaned up
struct Descriptor<Platform: sync::RawSyncPrimitivesProvider> {
    fd: super::resolver::ResolverFd<Platform, TarRo>,
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Descriptor<Platform>;
    -> FileFd<Platform>;
}
