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
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use tar_core::parse::{Limits, ParseError, ParseEvent, ParsedEntry, Parser};
use tar_core::{EntryType, PAX_GID, PAX_MTIME, PAX_SIZE, PAX_UID, PaxExtensions};

use super::{DirEntry, FileType};

use super::{
    Mode, NodeInfo, OFlags, UserInfo,
    backend::{
        CreationMetadata, DirHandle, FileHandle, HandleRef, PermissionCheck, PermissionInfo,
        Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
    },
    errors::{
        ChmodError, ChownError, MkdirError, OpenError, PathError, ReadDirError, ReadError,
        RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError,
        WalkError, WriteError,
    },
    inode_allocator::InodeAllocator,
};

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: u64 = 0;

/// A [`super::backend::Backend`] that stores all files in-memory, via a read-only `.tar` file.
pub struct TarRo {
    tar_index: TarIndex,
}

impl TarRo {
    fn resolved_dir<'a>(&self, dir: TarRoDirHandle) -> ResolvedDir<'a> {
        let indexed = &self.tar_index.dirs[dir.idx];
        let permissions = PermissionCheck::ByResolver(PermissionInfo {
            mode: indexed.mode,
            owner: indexed.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
            on_read_only_fs: true,
        });
        ResolvedDir::from_typed::<Self>(dir, permissions)
    }

    /// Construct a tar backend using a caller-provided inode allocator.
    ///
    /// Regular files, directories, symlinks and hard links (each name with its own inode) are
    /// indexed; other entry types (including sparse files), and entries with non-UTF-8 paths or
    /// `..` components, are skipped with a warning.
    ///
    /// # Panics
    ///
    /// Panics if `tar_data` is malformed or truncated, or archives two non-directories (or a
    /// directory and a non-directory) at the same path, or an entry beneath a non-directory.
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
    type ResolvedDir<'a> = TarRoDirHandle;
    type ResolvedFile<'a> = TarRoFileHandle;
    type FileHandle = TarRoFileHandle;
    type DirHandle = TarRoDirHandle;
}

impl super::backend::Backend for TarRo {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(self.resolved_dir(TarRoDirHandle { idx: 0 }))
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from;
        for (index, component) in components.iter().enumerate() {
            let fail = |error| ResolutionError {
                component: Some(index),
                error,
            };
            let PermissionCheck::ByResolver(permissions) = &current.permissions else {
                unreachable!()
            };
            authorize_dir_lookup(permissions).map_err(fail)?;
            let dir = current.into_typed::<Self>();
            match self.tar_index.dirs[dir.idx].children.get(*component) {
                Some(IndexedChild::Dir(idx)) => {
                    current = self.resolved_dir(TarRoDirHandle { idx: *idx });
                }
                Some(IndexedChild::File(idx)) => {
                    if index + 1 != components.len() {
                        return Err(ResolutionError {
                            component: Some(index + 1),
                            error: PathError::ComponentNotADirectory.into(),
                        });
                    }
                    let file = &self.tar_index.files[*idx];
                    return Ok(Resolution::Found(ResolvedTarget::File(
                        ResolvedFile::from_typed::<Self>(
                            TarRoFileHandle { idx: *idx },
                            PermissionCheck::ByResolver(PermissionInfo {
                                mode: file.mode,
                                owner: file.owner,
                                on_read_only_fs: true,
                            }),
                            file.file_type(),
                        ),
                    )));
                }
                None if index + 1 == components.len() => {
                    return Ok(Resolution::MissingFinal {
                        parent: self.resolved_dir(dir),
                    });
                }
                None => return Err(fail(PathError::NoSuchFileOrDirectory.into())),
            }
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        let dir = dir.get_typed::<Self>();
        match self.tar_index.dirs[dir.idx].children.get(name) {
            Some(IndexedChild::File(idx)) => match &self.tar_index.files[*idx].content {
                IndexedContent::Symlink(target) => Ok(target.clone()),
                IndexedContent::Regular(_) => Err(PathError::InvalidPathname.into()),
            },
            Some(IndexedChild::Dir(_)) => Err(PathError::InvalidPathname.into()),
            None => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        if flags.intersects(OFlags::CREAT | OFlags::TRUNC | OFlags::WRONLY | OFlags::RDWR) {
            return Err(OpenError::ReadOnlyFileSystem);
        }
        Ok(DirHandle::from_typed::<Self>(dir.into_typed::<Self>()))
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        Some(self.resolved_dir(dir.get_typed::<Self>().clone()))
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
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
        Ok(FileHandle::from_typed::<Self>(file.into_typed::<Self>()))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        Ok(self.tar_index.dirs[handle.idx]
            .children
            .iter()
            .map(|(name, child)| self.tar_index.dir_entry(name, *child))
            .collect())
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        Ok(self.tar_index.dirs[dir.get_typed::<Self>().idx]
            .children
            .get_key_value(name)
            .map(|(name, child)| self.tar_index.dir_entry(name, *child)))
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let file = self.tar_index.file_data(h.get_typed::<Self>().idx);
        let start = offset.min(file.len());
        let end = offset.checked_add(buf.len()).unwrap().min(file.len());
        debug_assert!(start <= end);
        let len = end - start;
        buf.copy_from_slice_at(0, &file[start..end])?;
        Ok(len)
    }

    fn write(
        &self,
        _h: &FileHandle,
        _buf: &dyn WriteBuffer,
        _offset: usize,
    ) -> Result<usize, WriteError> {
        Err(WriteError::NotForWriting)
    }

    fn truncate(&self, _h: &FileHandle, _length: usize) -> Result<(), TruncateError> {
        Err(TruncateError::NotForWriting)
    }

    fn seek_behavior(&self, _h: &FileHandle) -> super::backend::SeekBehavior {
        super::backend::SeekBehavior::PositionBased
    }

    fn status(
        &self,
        h: HandleRef<'_>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match h {
            HandleRef::File(h) => {
                let idx = h.get_typed::<Self>().idx;
                let file = &self.tar_index.files[idx];
                Ok(super::FileStatus {
                    file_type: file.file_type(),
                    mode: file.mode,
                    size: u64::try_from(self.tar_index.file_data(idx).len())
                        .map_err(|_| super::errors::FileStatusError::Io)?,
                    owner: file.owner,
                    node_info: file.node_info,
                    blksize: BLOCK_SIZE,
                })
            }
            HandleRef::Dir(h) => {
                let dir = &self.tar_index.dirs[h.get_typed::<Self>().idx];
                Ok(super::FileStatus {
                    file_type: FileType::Directory,
                    mode: dir.mode,
                    size: super::DEFAULT_DIRECTORY_SIZE,
                    owner: dir.owner.unwrap_or(DEFAULT_DIRECTORY_OWNER),
                    node_info: dir.node_info,
                    blksize: BLOCK_SIZE,
                })
            }
        }
    }

    fn resolved_status(
        &self,
        target: &ResolvedTarget<'_>,
    ) -> Result<super::FileStatus, super::errors::FileStatusError> {
        match target {
            ResolvedTarget::File(h) => self.status(HandleRef::File(
                &FileHandle::from_typed::<Self>(h.get_typed::<Self>().clone()),
            )),
            ResolvedTarget::Dir(h) => self.status(HandleRef::Dir(&DirHandle::from_typed::<Self>(
                h.get_typed::<Self>().clone(),
            ))),
        }
    }

    fn create_file_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Err(OpenError::ReadOnlyFileSystem)
    }

    fn symlink_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _target: &str,
        _metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        Err(SymlinkError::ReadOnlyFileSystem)
    }

    fn mkdir_at(
        &self,
        _dir: ResolvedDir<'_>,
        _name: &str,
        _metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        Err(MkdirError::ReadOnlyFileSystem)
    }

    fn unlink_at(&self, _dir: ResolvedDir<'_>, _name: &str) -> Result<(), UnlinkError> {
        Err(UnlinkError::ReadOnlyFileSystem)
    }

    fn rmdir_at(&self, _dir: ResolvedDir<'_>, _name: &str) -> Result<(), RmdirError> {
        Err(RmdirError::ReadOnlyFileSystem)
    }

    fn rename_at(
        &self,
        _old_dir: DirHandle,
        _old_name: &str,
        _new_dir: DirHandle,
        _new_name: &str,
    ) -> Result<(), RenameError> {
        Err(RenameError::ReadOnlyFileSystem)
    }

    fn chmod(&self, _h: ResolvedTarget<'_>, _mode: Mode) -> Result<(), ChmodError> {
        Err(ChmodError::ReadOnlyFileSystem)
    }

    fn chown(
        &self,
        _h: ResolvedTarget<'_>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        Err(ChownError::ReadOnlyFileSystem)
    }
}

/// An empty tar file to support an empty file system.
pub const EMPTY_TAR_FILE: &[u8] = &[0u8; 10240];

struct IndexedFile {
    content: IndexedContent,
    mode: Mode,
    owner: UserInfo,
    node_info: NodeInfo,
}

#[derive(Clone)]
enum IndexedContent {
    /// A regular file, whose data is this range of the archive.
    Regular(Range<usize>),
    /// A symlink, with its target as stored in the archive.
    Symlink(String),
}

impl IndexedFile {
    fn file_type(&self) -> FileType {
        match self.content {
            IndexedContent::Regular(_) => FileType::RegularFile,
            IndexedContent::Symlink(_) => FileType::SymbolicLink,
        }
    }
}

struct IndexedDir {
    mode: Mode,
    /// Set by the directory's own archive entry, or else by the first entry beneath it.
    owner: Option<UserInfo>,
    node_info: NodeInfo,
    children: HashMap<String, IndexedChild>,
}

impl IndexedDir {
    fn new(owner: Option<UserInfo>, inode_allocator: &InodeAllocator) -> Self {
        Self {
            mode: DEFAULT_DIR_MODE,
            owner,
            node_info: inode_allocator.next(),
            children: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy)]
enum IndexedChild {
    File(usize),
    Dir(usize),
}

struct TarIndex {
    tar_data: alloc::borrow::Cow<'static, [u8]>,
    files: Vec<IndexedFile>,
    /// The root directory is at index 0.
    dirs: Vec<IndexedDir>,
}

impl TarIndex {
    /// Index every entry of `tar_data`, panicking if the archive is malformed.
    fn new(tar_data: alloc::borrow::Cow<'static, [u8]>, inode_allocator: InodeAllocator) -> Self {
        let mut index = Self {
            tar_data: alloc::borrow::Cow::Borrowed(&[]),
            files: Vec::new(),
            dirs: alloc::vec![IndexedDir::new(None, &inode_allocator)],
        };
        for entry in archive_entries(&tar_data) {
            let (entry, data_range) = entry.unwrap_or_else(|error| panic!("{error}"));
            index.insert(&entry, data_range, &inode_allocator);
        }
        index.tar_data = tar_data;
        index
    }

    /// Index `entry`, whose content is `data_range` of the archive.
    fn insert(
        &mut self,
        entry: &ParsedEntry<'_>,
        data_range: Range<usize>,
        inode_allocator: &InodeAllocator,
    ) {
        let Ok(path) = core::str::from_utf8(&entry.path) else {
            litebox_util_log::warn!(path:? = entry.path_lossy(); "skipping non-UTF-8 tar path");
            return;
        };
        let Some(components) = path_components(path) else {
            litebox_util_log::warn!(path = path; "skipping tar path containing `..`");
            return;
        };
        let mode = Mode::from_bits_truncate(u16::try_from(entry.mode & 0o777).unwrap());
        let owner = UserInfo {
            user: u16::try_from(entry.uid).unwrap_or(OVERFLOW_ID),
            group: u16::try_from(entry.gid).unwrap_or(OVERFLOW_ID),
        };
        let (content, mode, file_owner) = match entry.entry_type {
            EntryType::Directory => {
                let dir = self.dir_at(path, &components, owner, inode_allocator);
                self.dirs[dir].mode = mode;
                self.dirs[dir].owner = Some(owner);
                return;
            }
            EntryType::Regular | EntryType::Continuous => {
                (IndexedContent::Regular(data_range), mode, owner)
            }
            EntryType::Symlink => {
                let target = entry.link_target.as_deref().unwrap_or_default();
                let Ok(target) = core::str::from_utf8(target) else {
                    litebox_util_log::warn!(path = path; "skipping symlink with non-UTF-8 target");
                    return;
                };
                if target.is_empty() || target.contains('\0') {
                    litebox_util_log::warn!(path = path; "skipping symlink with invalid target");
                    return;
                }
                (IndexedContent::Symlink(target.into()), SYMLINK_MODE, owner)
            }
            EntryType::Link => {
                let target = entry.link_target.as_deref().unwrap_or_default();
                // The already-indexed node at the target, without following symlinks.
                let file = core::str::from_utf8(target)
                    .ok()
                    .and_then(path_components)
                    .and_then(|target| {
                        target
                            .iter()
                            .try_fold(IndexedChild::Dir(0), |node, component| match node {
                                IndexedChild::Dir(dir) => {
                                    self.dirs[dir].children.get(*component).copied()
                                }
                                IndexedChild::File(_) => None,
                            })
                    });
                let Some(IndexedChild::File(file)) = file else {
                    litebox_util_log::warn!(
                        path = path, target:? = entry.link_target_lossy();
                        "skipping hard link to a missing or non-file target"
                    );
                    return;
                };
                // Each name gets its own inode: `Overlay` copies up per name, so names sharing an
                // inode would diverge in content and metadata while still reporting one inode.
                let file = &self.files[file];
                (file.content.clone(), file.mode, file.owner)
            }
            entry_type => {
                litebox_util_log::warn!(
                    path = path, entry_type:? = entry_type;
                    "skipping unsupported tar entry type"
                );
                return;
            }
        };
        let Some((name, parent)) = components.split_last() else {
            panic!("tar entry {path:?} names the root directory but is not a directory")
        };
        let parent = self.dir_at(path, parent, owner, inode_allocator);
        let file = IndexedChild::File(self.files.len());
        self.files.push(IndexedFile {
            content,
            mode,
            owner: file_owner,
            node_info: inode_allocator.next(),
        });
        let previous = self.dirs[parent].children.insert((*name).into(), file);
        assert!(previous.is_none(), "tar entry {path:?} is a duplicate");
    }

    /// The directory at `components`, creating it and its ancestors as needed, owned by `owner`
    /// unless already owned.
    fn dir_at(
        &mut self,
        path: &str,
        components: &[&str],
        owner: UserInfo,
        inode_allocator: &InodeAllocator,
    ) -> usize {
        let mut dir = 0;
        for component in components {
            self.dirs[dir].owner.get_or_insert(owner);
            dir = match self.dirs[dir].children.get(*component) {
                Some(IndexedChild::Dir(child)) => *child,
                Some(IndexedChild::File(_)) => {
                    panic!("tar entry {path:?} conflicts with a non-directory")
                }
                None => {
                    let child = self.dirs.len();
                    self.dirs
                        .push(IndexedDir::new(Some(owner), inode_allocator));
                    self.dirs[dir]
                        .children
                        .insert((*component).into(), IndexedChild::Dir(child));
                    child
                }
            };
        }
        self.dirs[dir].owner.get_or_insert(owner);
        dir
    }

    /// The content of a regular file, or the target of a symlink.
    fn file_data(&self, file_idx: usize) -> &[u8] {
        match &self.files[file_idx].content {
            IndexedContent::Regular(range) => &self.tar_data[range.clone()],
            IndexedContent::Symlink(target) => target.as_bytes(),
        }
    }

    /// The directory entry for `child`, named `name` in its parent.
    fn dir_entry(&self, name: &str, child: IndexedChild) -> DirEntry {
        let (file_type, node_info) = match child {
            IndexedChild::File(idx) => (self.files[idx].file_type(), self.files[idx].node_info),
            IndexedChild::Dir(idx) => (FileType::Directory, self.dirs[idx].node_info),
        };
        DirEntry {
            name: name.into(),
            file_type,
            ino_info: Some(node_info),
        }
    }
}

/// A tar archive that is malformed or truncated.
#[derive(Debug, thiserror::Error)]
pub enum MalformedArchive {
    #[error("invalid tar data at offset {offset}: {error}")]
    Invalid {
        offset: usize,
        error: tar_core::parse::ParseError,
    },
    #[error("truncated tar data at offset {0}")]
    Truncated(usize),
    #[error("tar entry {0:?} is too large")]
    TooLarge(String),
    #[error("tar entry {0:?} extends past the archive")]
    PastEnd(String),
}

/// The entries of the in-memory tar archive `data`, each with the range of `data` holding its
/// content. Sparse entries are skipped with a warning. Iteration ends after the first error.
pub fn archive_entries(
    data: &[u8],
) -> impl Iterator<Item = Result<(ParsedEntry<'_>, Range<usize>), MalformedArchive>> {
    let mut parser = Parser::new(Limits::default());
    let mut lenient_parser = Parser::new(Limits::default());
    lenient_parser.set_ignore_pax_errors(true);
    // `None` once iteration has ended.
    let mut offset = Some(0);
    core::iter::from_fn(move || {
        loop {
            let current = offset.take()?;
            let input = &data[current..];
            let event = match parser.parse(input) {
                // tar-core rejects a negative (pre-epoch) PAX `mtime`, which is valid. Timestamps
                // are unused here, so such an entry is parsed again ignoring invalid PAX values,
                // and the ones that matter are checked separately.
                Err(ParseError::InvalidPaxValue { key: PAX_MTIME, .. }) => {
                    lenient_parser.parse(input).and_then(|event| {
                        if let ParseEvent::Entry { entry, .. }
                        | ParseEvent::SparseEntry { entry, .. } = &event
                        {
                            check_pax_numbers(entry)?;
                        }
                        Ok(event)
                    })
                }
                result => result,
            };
            let event = match event {
                Ok(event) => event,
                Err(error) => {
                    return Some(Err(MalformedArchive::Invalid {
                        offset: current,
                        error,
                    }));
                }
            };
            let (consumed, entry, is_sparse) = match event {
                // An archive may end at a block boundary without its end-of-archive marker.
                ParseEvent::NeedData { .. } if input.is_empty() => return None,
                ParseEvent::NeedData { .. } => {
                    return Some(Err(MalformedArchive::Truncated(current)));
                }
                ParseEvent::End { .. } => return None,
                ParseEvent::GlobalExtensions { consumed, .. } => {
                    offset = Some(current + consumed);
                    continue;
                }
                ParseEvent::Entry { consumed, entry } => (consumed, entry, false),
                ParseEvent::SparseEntry {
                    consumed, entry, ..
                } => (consumed, entry, true),
            };
            let start = current + consumed;
            // A PAX `size` override is not bounded by tar-core, so padding it can overflow.
            let (Ok(size), Some(padded_size)) = (
                usize::try_from(entry.size),
                entry
                    .size
                    .checked_next_multiple_of(512)
                    .and_then(|padded| usize::try_from(padded).ok()),
            ) else {
                return Some(Err(MalformedArchive::TooLarge(
                    entry.path_lossy().into_owned(),
                )));
            };
            let Some(end) = start
                .checked_add(padded_size)
                .filter(|&end| end <= data.len())
            else {
                return Some(Err(MalformedArchive::PastEnd(
                    entry.path_lossy().into_owned(),
                )));
            };
            offset = Some(end);
            if is_sparse {
                litebox_util_log::warn!(
                    path:? = entry.path_lossy();
                    "skipping unsupported sparse tar entry"
                );
                continue;
            }
            return Some(Ok((entry, start..start + size)));
        }
    })
}

/// Fail as tar-core's strict parsing does on an invalid PAX `size`, `uid` or `gid` of `entry`,
/// which lenient parsing silently replaces with the header's value.
fn check_pax_numbers(entry: &ParsedEntry<'_>) -> Result<(), ParseError> {
    for extension in PaxExtensions::new(entry.pax.unwrap_or_default()) {
        let extension = extension?;
        let key = match extension.key()? {
            PAX_SIZE => PAX_SIZE,
            PAX_UID => PAX_UID,
            PAX_GID => PAX_GID,
            _ => continue,
        };
        let value = extension.value()?;
        if value.parse::<u64>().is_err() {
            return Err(ParseError::InvalidPaxValue {
                key,
                value: String::from(value).into(),
            });
        }
    }
    Ok(())
}

/// The components of the archive path `path`, relative to the root; `None` if `path` contains
/// `..`.
///
/// Leading `/`, `.` components and empty components are dropped, so `.`, `./` and `/` all name the
/// root directory.
fn path_components(path: &str) -> Option<Vec<&str>> {
    path.split('/')
        .filter(|component| !matches!(*component, "" | "."))
        .map(|component| (component != "..").then_some(component))
        .collect()
}

const DEFAULT_DIR_MODE: Mode =
    Mode::from_bits(Mode::RWXU.bits() | Mode::RWXG.bits() | Mode::RWXO.bits()).unwrap();

const SYMLINK_MODE: Mode = DEFAULT_DIR_MODE;

const DEFAULT_DIRECTORY_OWNER: UserInfo = UserInfo {
    user: 1000,
    group: 1000,
};

/// The id that archived user and group ids beyond `u16` map to: Linux's default overflow id.
const OVERFLOW_ID: u16 = 65534;
