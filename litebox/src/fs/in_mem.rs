// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::LiteBox;
use crate::path::Arg;
use crate::sync;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, SeekWhence, UserInfo};

/// A [`super::backend::Backend`] that stores all files in memory.
///
/// # Warning
///
/// This has no physical backing store, thus any files in memory are erased as soon as this object
/// is dropped.
pub struct InMem<Platform: sync::RawSyncPrimitivesProvider> {
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: DirNode<Platform>,
    // TODO(jayb): This duplicates the resolver's `Context::user_info`, and the two can disagree.
    // The resolver should own the acting user and pass it down: it needs to (a) supply the owner
    // for newly created files/dirs, (b) check write permission on the parent before
    // create/mkdir/unlink/rmdir, and (c) perform the root-or-owner check for chmod/chown. Once it
    // does, this field (and `with_root_privileges`/`with_user`) can go away.
    current_user: UserInfo,
    inode_allocator: InodeAllocator,
}

impl<Platform: sync::RawSyncPrimitivesProvider> InMem<Platform> {
    /// Construct a new `InMem` backend.
    #[must_use]
    pub fn new(inode_allocator: InodeAllocator) -> Self {
        let root = Arc::new(sync::RwLock::new(DirData {
            perms: Permissions {
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                userinfo: UserInfo::ROOT,
            },
            children: HashMap::default(),
            node_info: inode_allocator.next(),
        }));
        Self {
            root,
            current_user: UserInfo {
                user: 1000,
                group: 1000,
            },
            inode_allocator,
        }
    }

    /// Execute `f` with superuser/root privileges.
    ///
    /// This function primarily exists to initialize files. Most regular interaction with the file
    /// system should be done without this function.
    pub fn with_root_privileges<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let original_user = core::mem::replace(&mut self.current_user, UserInfo::ROOT);
        f(self);
        let root_again = core::mem::replace(&mut self.current_user, original_user);
        if root_again.user != UserInfo::ROOT.user || root_again.group != UserInfo::ROOT.group {
            unreachable!()
        }
    }

    /// Initialize a primarily read-heavy file with static data.
    ///
    /// While this function could technically work with write-heavy files, it has performance
    /// benefits _particularly_ for files that are read-only, compared to doing open+write
    /// operations.
    ///
    /// The file is initialized with clone-on-write semantics for the data, meaning that the first
    /// time a write occurs on the file, it suffers the penalty of the entire data being cloned into
    /// memory, which is why this is intended primarily for read-only files (such as executables).
    ///
    /// # Panics
    ///
    /// Panics if used on a file that already contains data.
    pub fn initialize_primarily_read_heavy_file(
        &self,
        h: &super::backend::FileHandle,
        data: alloc::borrow::Cow<'static, [u8]>,
    ) {
        let mut file = h.get_typed::<Self>().file.write();
        assert!(
            file.data.is_empty(),
            "must only be used on empty files during initialization"
        );
        file.data = data;
    }

    /// Execute `f` as a specific user (for testing purposes).
    #[cfg(test)]
    pub fn with_user<F>(&mut self, user: u16, group: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let test_user = UserInfo { user, group };
        let original_user = core::mem::replace(&mut self.current_user, test_user);
        f(self);
        let test_user_again = core::mem::replace(&mut self.current_user, original_user);
        if test_user_again.user != test_user.user || test_user_again.group != test_user.group {
            unreachable!()
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::backend::private::Sealed
    for InMem<Platform>
{
}

/// Directory handle
pub struct InMemDirHandle<Platform: sync::RawSyncPrimitivesProvider> {
    dir: DirNode<Platform>,
    /// The flags the directory was opened with; walking handles are not opened for access, and
    /// thus use [`super::OFlags::PATH`].
    flags: super::OFlags,
}
impl<Platform: sync::RawSyncPrimitivesProvider> Clone for InMemDirHandle<Platform> {
    fn clone(&self) -> Self {
        Self {
            dir: self.dir.clone(),
            flags: self.flags,
        }
    }
}

/// File handle
pub struct InMemFileHandle<Platform: sync::RawSyncPrimitivesProvider> {
    file: FileNode<Platform>,
}
impl<Platform: sync::RawSyncPrimitivesProvider> Clone for InMemFileHandle<Platform> {
    fn clone(&self) -> Self {
        Self {
            file: self.file.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::backend::BackendHandles for InMem<Platform> {
    type WalkingDirHandle<'a> = InMemDirHandle<Platform>;
    type FileHandle = InMemFileHandle<Platform>;
    type DirHandle = InMemDirHandle<Platform>;
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::backend::Backend for InMem<Platform> {
    fn root(&self) -> super::backend::WalkingDirHandle<'_> {
        super::backend::WalkingDirHandle::from_typed::<Self>(InMemDirHandle {
            dir: self.root.clone(),
            flags: super::OFlags::PATH,
        })
    }

    fn walk_directories<'a>(
        &'a self,
        from: super::backend::WalkingDirHandle<'a>,
        components: &[&str],
    ) -> Result<
        super::backend::WalkOutcome<super::backend::WalkingDirHandle<'a>>,
        super::errors::WalkError,
    > {
        let mut current = from.into_typed::<Self>();
        let mut walked_components = Vec::with_capacity(components.len());
        for component in components {
            let child = current
                .dir
                .read()
                .children
                .get(*component)
                .ok_or(PathError::NoSuchFileOrDirectory)?
                .clone();
            let Node::Dir(child) = child else {
                return Ok(super::backend::WalkOutcome {
                    components: walked_components,
                    last: super::backend::WalkingDirHandle::from_typed::<Self>(current),
                    stop_reason: super::backend::WalkStopReason::StoppedAtNonDirectory,
                });
            };
            let perms = child.read().perms.clone();
            walked_components.push(super::backend::WalkedComponent {
                permissions: super::backend::PermissionCheck::ByResolver(
                    super::backend::PermissionInfo {
                        mode: perms.mode,
                        owner: perms.userinfo,
                    },
                ),
            });
            current = InMemDirHandle {
                dir: child,
                flags: super::OFlags::PATH,
            };
        }
        Ok(super::backend::WalkOutcome {
            components: walked_components,
            last: super::backend::WalkingDirHandle::from_typed::<Self>(current),
            stop_reason: super::backend::WalkStopReason::CompleteDirectory,
        })
    }

    fn owned_dir_at(
        &self,
        dir: super::backend::WalkingDirHandle<'_>,
        flags: super::OFlags,
    ) -> Result<super::backend::DirHandle, OpenError> {
        assert_supported_oflags(flags);
        if flags.intersects(super::OFlags::WRONLY | super::OFlags::RDWR) {
            // TODO(jayb): POSIX requires `EISDIR` when write access is requested on a directory,
            // but `OpenError` has no such variant yet.
            unimplemented!()
        }
        Ok(super::backend::DirHandle::from_typed::<Self>(
            InMemDirHandle {
                flags,
                ..dir.into_typed::<Self>()
            },
        ))
    }

    fn walking_dir_at<'a>(
        &'a self,
        dir: &super::backend::DirHandle,
    ) -> Option<super::backend::WalkingDirHandle<'a>> {
        Some(super::backend::WalkingDirHandle::from_typed::<Self>(
            InMemDirHandle {
                dir: dir.get_typed::<Self>().dir.clone(),
                flags: super::OFlags::PATH,
            },
        ))
    }

    fn open_file_at(
        &self,
        dir: super::backend::WalkingDirHandle<'_>,
        name: &str,
        flags: super::OFlags,
    ) -> Result<super::backend::Permissioned<super::backend::FileHandle>, OpenError> {
        assert_supported_oflags(flags);
        let dir = dir.into_typed::<Self>();
        let child = dir
            .dir
            .read()
            .children
            .get(name)
            .ok_or(PathError::NoSuchFileOrDirectory)?
            .clone();
        let Node::File(file) = child else {
            return Err(PathError::ComponentNotADirectory.into());
        };
        if flags.contains(super::OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let perms = file.read().perms.clone();
        let handle = super::backend::FileHandle::from_typed::<Self>(InMemFileHandle { file });
        if flags.contains(super::OFlags::TRUNC) && !flags.contains(super::OFlags::PATH) {
            // Linux truncates whenever the open succeeds, regardless of the access mode (an
            // `O_RDONLY|O_TRUNC` open of a writable file does truncate it); `O_PATH` opens ignore
            // `O_TRUNC` entirely.
            //
            // TODO(jayb): Linux's `may_open` also adds `MAY_WRITE` for `O_TRUNC`, and checks
            // permissions _before_ truncating; the resolver does neither, so a denied
            // `O_RDONLY|O_TRUNC` open still empties the file here.
            self.truncate(&handle, 0)?;
        }
        Ok(super::backend::Permissioned {
            item: handle,
            permissions: super::backend::PermissionCheck::ByResolver(
                super::backend::PermissionInfo {
                    mode: perms.mode,
                    owner: perms.userinfo,
                },
            ),
        })
    }

    fn list_dir_at(
        &self,
        handle: super::backend::DirHandle,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        Ok(handle
            .into_typed::<Self>()
            .dir
            .read()
            .children
            .iter()
            .map(|(name, child)| {
                let (file_type, node_info) = match child {
                    Node::File(file) => (FileType::RegularFile, file.read().node_info.clone()),
                    Node::Dir(dir) => (FileType::Directory, dir.read().node_info.clone()),
                };
                DirEntry {
                    name: name.clone(),
                    file_type,
                    ino_info: Some(node_info),
                }
            })
            .collect())
    }

    fn read(
        &self,
        h: &super::backend::FileHandle,
        buf: &mut [u8],
        offset: usize,
    ) -> Result<usize, ReadError> {
        let file = h.get_typed::<Self>().file.read();
        let start = offset.min(file.data.len());
        let end = offset.checked_add(buf.len()).unwrap().min(file.data.len());
        debug_assert!(start <= end);
        let len = end - start;
        buf[..len].copy_from_slice(&file.data[start..end]);
        Ok(len)
    }

    fn write(
        &self,
        h: &super::backend::FileHandle,
        buf: &[u8],
        offset: usize,
    ) -> Result<usize, WriteError> {
        let mut file = h.get_typed::<Self>().file.write();
        let overwritten_len = match offset.cmp(&file.data.len()) {
            core::cmp::Ordering::Less => {
                let end = offset.checked_add(buf.len()).unwrap().min(file.data.len());
                let overwritten_len = end - offset;
                file.data.to_mut()[offset..end].copy_from_slice(&buf[..overwritten_len]);
                overwritten_len
            }
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => {
                // Need to pad with 0s because the offset was past the end of the file
                file.data.to_mut().resize(offset, 0);
                0
            }
        };
        file.data.to_mut().extend(&buf[overwritten_len..]);
        Ok(buf.len())
    }

    fn truncate(&self, h: &super::backend::FileHandle, length: usize) -> Result<(), TruncateError> {
        let mut file = h.get_typed::<Self>().file.write();
        match length.cmp(&file.data.len()) {
            core::cmp::Ordering::Less => match &mut file.data {
                alloc::borrow::Cow::Borrowed(d) => *d = &d[..length],
                alloc::borrow::Cow::Owned(d) => d.truncate(length),
            },
            core::cmp::Ordering::Equal => (),
            core::cmp::Ordering::Greater => file.data.to_mut().resize(length, 0),
        }
        Ok(())
    }

    fn seek_behavior(&self, _h: &super::backend::FileHandle) -> super::backend::SeekBehavior {
        super::backend::SeekBehavior::PositionBased
    }

    fn status(&self, h: super::backend::HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            super::backend::HandleRef::File(h) => {
                let file = h.get_typed::<Self>().file.read();
                Ok(FileStatus {
                    file_type: FileType::RegularFile,
                    mode: file.perms.mode,
                    size: file.data.len(),
                    owner: file.perms.userinfo,
                    node_info: file.node_info.clone(),
                    blksize: BLOCK_SIZE,
                })
            }
            super::backend::HandleRef::Dir(h) => {
                let dir = h.get_typed::<Self>().dir.read();
                Ok(FileStatus {
                    file_type: FileType::Directory,
                    mode: dir.perms.mode,
                    size: super::DEFAULT_DIRECTORY_SIZE,
                    owner: dir.perms.userinfo,
                    node_info: dir.node_info.clone(),
                    blksize: BLOCK_SIZE,
                })
            }
        }
    }

    fn create_file_at(
        &self,
        dir: super::backend::DirHandle,
        name: &str,
        mode: Mode,
    ) -> Result<super::backend::FileHandle, OpenError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before creating;
        // the resolver should do so before calling this.
        let file = Arc::new(sync::RwLock::new(FileData {
            perms: Permissions {
                mode,
                userinfo: self.current_user,
            },
            data: Vec::new().into(),
            node_info: self.inode_allocator.next(),
        }));
        let old = dir
            .into_typed::<Self>()
            .dir
            .write()
            .children
            .insert(name.into(), Node::File(file.clone()));
        assert!(old.is_none());
        Ok(super::backend::FileHandle::from_typed::<Self>(
            InMemFileHandle { file },
        ))
    }

    fn mkdir_at(
        &self,
        dir: super::backend::DirHandle,
        name: &str,
        mode: Mode,
    ) -> Result<super::backend::DirHandle, MkdirError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before creating;
        // the resolver should do so before calling this.
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        if parent.children.contains_key(name) {
            return Err(MkdirError::AlreadyExists);
        }
        let child = Arc::new(sync::RwLock::new(DirData {
            perms: Permissions {
                mode,
                userinfo: self.current_user,
            },
            children: HashMap::default(),
            node_info: self.inode_allocator.next(),
        }));
        parent
            .children
            .insert(name.into(), Node::Dir(child.clone()));
        Ok(super::backend::DirHandle::from_typed::<Self>(
            InMemDirHandle {
                dir: child,
                // TODO(jayb): is this the right set of flags here?
                flags: super::OFlags::PATH,
            },
        ))
    }

    fn unlink_at(&self, dir: super::backend::DirHandle, name: &str) -> Result<(), UnlinkError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before removing;
        // the resolver should do so before calling this.
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        match parent.children.get(name) {
            None => Err(PathError::NoSuchFileOrDirectory.into()),
            Some(Node::Dir(_)) => Err(UnlinkError::IsADirectory),
            Some(Node::File(_)) => {
                parent.children.remove(name);
                Ok(())
            }
        }
    }

    fn rmdir_at(&self, dir: super::backend::DirHandle, name: &str) -> Result<(), RmdirError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before removing;
        // the resolver should do so before calling this.
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        match parent.children.get(name) {
            None => Err(PathError::NoSuchFileOrDirectory.into()),
            Some(Node::File(_)) => Err(RmdirError::NotADirectory),
            Some(Node::Dir(child)) if !child.read().children.is_empty() => {
                Err(RmdirError::NotEmpty)
            }
            Some(Node::Dir(_)) => {
                parent.children.remove(name);
                Ok(())
            }
        }
    }

    fn chmod(&self, h: super::backend::HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        // TODO(jayb): This checks ownership against the backend's own `current_user`, rather than
        // the resolver's context user.
        let mut perms = match h {
            super::backend::HandleRef::File(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().file.write(), |f| &mut f.perms)
            }
            super::backend::HandleRef::Dir(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().dir.write(), |d| &mut d.perms)
            }
        };
        if !(self.current_user.user == UserInfo::ROOT.user
            || self.current_user.user == perms.userinfo.user)
        {
            return Err(ChmodError::NotTheOwner);
        }
        perms.mode = mode;
        Ok(())
    }

    fn chown(
        &self,
        h: super::backend::HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        // TODO(jayb): This checks ownership against the backend's own `current_user`, rather than
        // the resolver's context user.
        let mut perms = match h {
            super::backend::HandleRef::File(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().file.write(), |f| &mut f.perms)
            }
            super::backend::HandleRef::Dir(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().dir.write(), |d| &mut d.perms)
            }
        };
        if !(self.current_user.user == UserInfo::ROOT.user
            || self.current_user.user == perms.userinfo.user)
        {
            return Err(ChownError::NotTheOwner);
        }
        if let Some(new_user) = user {
            perms.userinfo.user = new_user;
        }
        if let Some(new_group) = group {
            perms.userinfo.group = new_group;
        }
        Ok(())
    }

    fn get_static_backing_data(&self, h: &super::backend::FileHandle) -> Option<&'static [u8]> {
        match h.get_typed::<Self>().file.read().data {
            alloc::borrow::Cow::Borrowed(slice) => Some(slice),
            alloc::borrow::Cow::Owned(_) => None,
        }
    }
}

/// Flags this backend knows how to honor when opening files/directories.
const SUPPORTED_OFLAGS: super::OFlags = super::OFlags::CREAT
    .union(super::OFlags::RDONLY)
    .union(super::OFlags::WRONLY)
    .union(super::OFlags::RDWR)
    .union(super::OFlags::TRUNC)
    .union(super::OFlags::NOCTTY)
    .union(super::OFlags::EXCL)
    .union(super::OFlags::DIRECTORY)
    .union(super::OFlags::NONBLOCK)
    .union(super::OFlags::LARGEFILE)
    .union(super::OFlags::NOFOLLOW)
    .union(super::OFlags::APPEND)
    .union(super::OFlags::PATH);

fn assert_supported_oflags(flags: super::OFlags) {
    if flags.intersects(SUPPORTED_OFLAGS.complement()) {
        unimplemented!("{flags:?}")
    }
}

/// Just a random constant that is distinct from other file systems. In this case, it is
/// `b'IMem'.hex()`.
const DEVICE_ID: usize = 0x494d656d;

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

/// A backing implementation for [`FileSystem`](super::FileSystem) storing all files in-memory.
///
/// # Warning
///
/// This has no physical backing store, thus any files in memory are erased as soon as this object
/// is dropped.
pub struct FileSystem<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: sync::RwLock<Platform, RootDir<Platform>>,
    current_user: UserInfo,
    // cwd invariant: always ends with a `/`
    current_working_dir: String,
    // a source of freshness for providing unique IDs
    unique_id_freshness: core::sync::atomic::AtomicUsize,
}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    /// Construct a new `FileSystem` instance
    ///
    /// This function is expected to only be invoked once per platform, as an initialiation step,
    /// and the created `FileSystem` handle is expected to be shared across all usage over the
    /// system.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>) -> Self {
        let litebox = litebox.clone();
        let root = sync::RwLock::new(RootDir::new());
        Self {
            litebox,
            root,
            current_user: UserInfo {
                user: 1000,
                group: 1000,
            },
            current_working_dir: "/".into(),
            unique_id_freshness: 1.into(), // the root dir gets unique ID of 0
        }
    }

    /// Execute `f` with superuser/root privileges.
    ///
    /// This function primarily exists to initialize files. Most regular interaction with the file
    /// system should be done without this function.
    pub fn with_root_privileges<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let original_user = core::mem::replace(&mut self.current_user, UserInfo::ROOT);
        f(self);
        let root_again = core::mem::replace(&mut self.current_user, original_user);
        if root_again.user != UserInfo::ROOT.user || root_again.group != UserInfo::ROOT.group {
            unreachable!()
        }
    }

    /// Initialize a primarily read-heavy file with static data.
    ///
    /// While this function could technically work with write-heavy files, it has performance
    /// benefits _particularly_ for files that are read-only, compared to doing open+write
    /// operations.
    ///
    /// The file is initialized with clone-on-write semantics for the data, meaning that the first
    /// time a write occurs on the file, it suffers the penalty of the entire data being cloned into
    /// memory, which is why this is intended primarily for read-only files (such as executables).
    ///
    /// # Panics
    ///
    /// Panics if used on
    /// - a closed FD
    /// - a non-file FD
    /// - a file that already contains data
    pub fn initialize_primarily_read_heavy_file(
        &mut self,
        fd: &FileFd<Platform>,
        data: alloc::borrow::Cow<'static, [u8]>,
    ) {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed: _,
            position: _,
            append_mode: _,
        } = &mut descriptor_table.get_entry_mut(fd).unwrap().entry
        else {
            panic!("must only be used on files, not directories")
        };
        let mut file = file.write();
        assert!(
            file.data.is_empty(),
            "must only be used on empty files during initialization"
        );
        file.data = data;
    }

    /// Execute `f` as a specific user (for testing purposes).
    #[cfg(test)]
    pub fn with_user<F>(&mut self, user: u16, group: u16, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let test_user = UserInfo { user, group };
        let original_user = core::mem::replace(&mut self.current_user, test_user);
        f(self);
        let test_user_again = core::mem::replace(&mut self.current_user, original_user);
        if test_user_again.user != test_user.user || test_user_again.group != test_user.group {
            unreachable!()
        }
    }

    /// (Private) Provide a fresh unique ID
    fn fresh_id(&self) -> usize {
        let res = self
            .unique_id_freshness
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        assert_ne!(
            res,
            usize::MAX,
            "we never expect to hit this, but if we do, someone has made way too many files in this session"
        );
        res
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::private::Sealed for FileSystem<Platform> {}

impl<Platform: sync::RawSyncPrimitivesProvider> FileSystem<Platform> {
    // Gives the absolute path for `path`, resolving any `.` or `..`s, and making sure to account
    // for any relative paths from current working directory.
    //
    // Note: does NOT account for symlinks.
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

impl<Platform: sync::RawSyncPrimitivesProvider> super::FileSystem for FileSystem<Platform> {
    fn open(
        &self,
        path: impl crate::path::Arg,
        mut flags: super::OFlags,
        mode: super::Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        use super::OFlags;
        let currently_supported_oflags: OFlags = OFlags::CREAT
            | OFlags::RDONLY
            | OFlags::WRONLY
            | OFlags::RDWR
            | OFlags::TRUNC
            | OFlags::NOCTTY
            | OFlags::EXCL
            | OFlags::DIRECTORY
            | OFlags::NONBLOCK
            | OFlags::LARGEFILE
            | OFlags::NOFOLLOW
            | OFlags::APPEND;
        if flags.intersects(currently_supported_oflags.complement()) {
            unimplemented!("{flags:?}")
        }
        let path = self.absolute_path(path)?;
        let (entry, created) = if flags.contains(OFlags::CREAT) {
            let mut root = self.root.write();
            let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
            if let Some(entry) = entry {
                if flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                (entry, false)
            } else {
                let Some((_, parent)) = parent else {
                    // Only `/` does not have a parent; any other scenario (e.g., missing ancestor)
                    // is handled already by a `PathError`. If `/` was passed, then it would have
                    // gotten `Some(entry)` out already. Thus, this is unreachable.
                    unreachable!()
                };
                let mut parent = parent.write();
                if !self.current_user.can_write(&parent.perms) {
                    return Err(OpenError::NoWritePerms);
                }
                // When both O_CREAT and O_DIRECTORY are specified in flags and the
                // file specified by pathname does not exist, open() will create a
                // regular file (i.e., O_DIRECTORY is ignored).
                flags.remove(OFlags::DIRECTORY);
                let old = parent.children.insert(
                    path.components().unwrap().last().unwrap().into(),
                    FileType::RegularFile,
                );
                assert!(old.is_none());
                let entry = Entry::File(Arc::new(sync::RwLock::new(FileX {
                    perms: Permissions {
                        mode,
                        userinfo: self.current_user,
                    },
                    data: Vec::new().into(),
                    unique_id: self.fresh_id(),
                })));
                let old = root.entries.insert(path, entry.clone());
                assert!(old.is_none());
                (entry, true)
            }
        } else {
            let root = self.root.read();
            let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
            let Some(entry) = entry else {
                return Err(PathError::NoSuchFileOrDirectory)?;
            };
            (entry, false)
        };
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = if access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR {
            if !created && !self.current_user.can_read(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        let write_allowed = if access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR {
            if !created && !self.current_user.can_write(&entry.perms()) {
                return Err(OpenError::AccessNotAllowed);
            }
            true
        } else {
            false
        };
        let append_mode = flags.contains(OFlags::APPEND);
        let fd = match entry {
            Entry::File(file) => {
                if flags.contains(OFlags::DIRECTORY) {
                    return Err(OpenError::PathError(PathError::ComponentNotADirectory));
                }
                self.litebox
                    .descriptor_table_mut()
                    .insert(Descriptor::File {
                        file: file.clone(),
                        read_allowed,
                        write_allowed,
                        position: 0,
                        append_mode,
                    })
            }
            Entry::Dir(dir) => self
                .litebox
                .descriptor_table_mut()
                .insert(Descriptor::Dir { dir: dir.clone() }),
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
        let Descriptor::File {
            file,
            read_allowed,
            write_allowed: _,
            position,
            append_mode: _,
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(ReadError::ClosedFd)?
            .entry
        else {
            return Err(ReadError::NotAFile);
        };
        if !*read_allowed {
            return Err(ReadError::NotForReading);
        }
        let position = offset.as_mut().unwrap_or(position);
        let file = file.read();
        let start = (*position).min(file.data.len());
        let end = position
            .checked_add(buf.len())
            .unwrap()
            .min(file.data.len());
        debug_assert!(start <= end);
        let retlen = end - start;
        buf[..retlen].copy_from_slice(&file.data[start..end]);
        *position = end;
        Ok(retlen)
    }

    fn write(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        mut offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            append_mode,
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(WriteError::ClosedFd)?
            .entry
        else {
            return Err(WriteError::NotAFile);
        };
        if !*write_allowed {
            return Err(WriteError::NotForWriting);
        }
        // For append mode, we always write at the end of the file.
        // Note: pwrite (offset != None) ignores append mode per POSIX.
        let mut file = file.write();
        let write_position = if *append_mode && offset.is_none() {
            file.data.len()
        } else {
            *offset.as_mut().unwrap_or(position)
        };
        let end_position = write_position.checked_add(buf.len()).unwrap();
        let start = if write_position < file.data.len() {
            let start = write_position;
            let end = end_position.min(file.data.len());
            debug_assert!(start <= end);
            let first_half_len = end - start;
            file.data.to_mut()[start..end].copy_from_slice(&buf[..first_half_len]);
            first_half_len
        } else {
            if write_position > file.data.len() {
                // Need to pad with 0s because position was past the end of the file
                file.data.to_mut().resize(write_position, 0);
            }
            0
        };
        file.data.to_mut().extend(&buf[start..]);
        // Update the file position for positional writes (not pwrite)
        if offset.is_none() {
            *position = end_position;
        }
        Ok(buf.len())
    }

    fn seek(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed: _,
            position,
            append_mode: _,
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(SeekError::ClosedFd)?
            .entry
        else {
            return Err(SeekError::NotAFile);
        };
        let file_len = file.read().data.len();
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
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::File {
            file,
            read_allowed: _,
            write_allowed,
            position,
            append_mode: _,
        } = &mut descriptor_table
            .get_entry_mut(fd)
            .ok_or(TruncateError::ClosedFd)?
            .entry
        else {
            return Err(TruncateError::IsDirectory);
        };
        if !*write_allowed {
            return Err(TruncateError::NotForWriting);
        }
        let mut file_data = file.write();
        match length.cmp(&file_data.data.len()) {
            core::cmp::Ordering::Less => match &mut file_data.data {
                alloc::borrow::Cow::Borrowed(d) => {
                    *d = &d[..length];
                }
                alloc::borrow::Cow::Owned(d) => d.truncate(length),
            },
            core::cmp::Ordering::Equal => (),
            core::cmp::Ordering::Greater => file_data.data.to_mut().resize(length, 0),
        }
        if reset_offset {
            *position = 0;
        }
        Ok(())
    }

    fn chmod(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), ChmodError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChmodError::NotTheOwner);
                }
                perms.mode = mode;
                Ok(())
            }
        }
    }

    fn chown(
        &self,
        path: impl crate::path::Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        match entry {
            Entry::File(file) => {
                let perms = &mut file.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChownError::NotTheOwner);
                }
                if let Some(new_user) = user {
                    perms.userinfo.user = new_user;
                }
                if let Some(new_group) = group {
                    perms.userinfo.group = new_group;
                }
                Ok(())
            }
            Entry::Dir(dir) => {
                let perms = &mut dir.write().perms;
                if !(self.current_user.user == 0 || self.current_user.user == perms.userinfo.user) {
                    return Err(ChownError::NotTheOwner);
                }
                if let Some(new_user) = user {
                    perms.userinfo.user = new_user;
                }
                if let Some(new_group) = group {
                    perms.userinfo.group = new_group;
                }
                Ok(())
            }
        }
    }

    fn unlink(&self, path: impl crate::path::Arg) -> Result<(), UnlinkError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_, parent)) = parent else {
            // Attempted to remove `/`
            return Err(UnlinkError::IsADirectory);
        };
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        if let Entry::Dir(_) = entry {
            return Err(UnlinkError::IsADirectory);
        }
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(UnlinkError::NoWritePerms);
        }
        let removed = parent
            .children
            .remove(path.components().unwrap().last().unwrap());
        // Just a sanity check
        assert!(matches!(removed, Some(FileType::RegularFile)));
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::File(File { .. })));
        Ok(())
    }

    fn mkdir(&self, path: impl crate::path::Arg, mode: super::Mode) -> Result<(), MkdirError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_parent_path, parent)) = parent else {
            // Attempted to make `/`
            return Err(MkdirError::AlreadyExists);
        };
        let None = entry else {
            return Err(MkdirError::AlreadyExists);
        };
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(MkdirError::NoWritePerms);
        }
        let old = parent.children.insert(
            path.components().unwrap().last().unwrap().into(),
            FileType::Directory,
        );
        assert!(old.is_none());
        let old = root.entries.insert(
            path,
            Entry::Dir(Arc::new(sync::RwLock::new(DirX {
                perms: Permissions {
                    mode,
                    userinfo: self.current_user,
                },
                children: HashMap::default(),
                unique_id: self.fresh_id(),
            }))),
        );
        assert!(old.is_none());
        Ok(())
    }

    fn rmdir(&self, path: impl crate::path::Arg) -> Result<(), RmdirError> {
        let path = self.absolute_path(path)?;
        let mut root = self.root.write();
        let (parent, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some((_, parent)) = parent else {
            // Attempted to remove `/`
            return Err(RmdirError::Busy);
        };
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let Entry::Dir(dir) = entry else {
            return Err(RmdirError::NotADirectory);
        };
        if !dir.read().children.is_empty() {
            return Err(RmdirError::NotEmpty);
        }
        let mut parent = parent.write();
        if !self.current_user.can_write(&parent.perms) {
            return Err(RmdirError::NoWritePerms);
        }
        let removed = parent
            .children
            .remove(path.components().unwrap().last().unwrap());
        // Just a sanity check
        assert!(matches!(removed, Some(FileType::Directory)));
        let removed = root.entries.remove(&path).unwrap();
        // Just a sanity check
        assert!(matches!(removed, Entry::Dir(_)));
        Ok(())
    }

    fn read_dir(&self, fd: &FileFd<Platform>) -> Result<Vec<DirEntry>, ReadDirError> {
        let descriptor_table = self.litebox.descriptor_table();
        let Descriptor::Dir { dir } = &descriptor_table
            .get_entry(fd)
            .ok_or(ReadDirError::ClosedFd)?
            .entry
        else {
            return Err(ReadDirError::NotADirectory);
        };

        // find the directory path in the root entries by pointer-equality of the Arc
        let mut parent_path = {
            let root = self.root.read();
            root.entries
                .iter()
                .find_map(|(path, entry)| match entry {
                    Entry::Dir(d) if alloc::sync::Arc::ptr_eq(d, dir) => Some(path.clone()),
                    _ => None,
                })
                .unwrap_or(String::new())
        };

        // helper to get NodeInfo by an entries-key (entries keys have no trailing '/')
        let get_node_info = |key: &str| -> Option<NodeInfo> {
            self.root.read().entries.get(key).map(|entry| {
                let ino = match entry {
                    Entry::File(file) => file.read().unique_id,
                    Entry::Dir(dir) => dir.read().unique_id,
                };
                NodeInfo {
                    dev: DEVICE_ID,
                    ino,
                    rdev: None,
                }
            })
        };

        let mut entries: Vec<DirEntry> = Vec::new();

        // Add "."
        entries.push(DirEntry {
            name: ".".into(),
            file_type: FileType::Directory,
            ino_info: Some(NodeInfo {
                dev: DEVICE_ID,
                ino: dir.read().unique_id,
                rdev: None,
            }),
        });

        // Add ".."
        entries.push(DirEntry {
            name: "..".into(),
            file_type: FileType::Directory,
            ino_info: get_node_info(&parent_path),
        });

        // Append a trailing '/' to `parent_path`.
        // An empty string (`""`) represents the root.
        parent_path.push('/');

        // Add normal children
        entries.extend(dir.read().children.iter().map(|(name, file_type)| {
            let mut full_path = parent_path.clone();
            full_path.push_str(name);
            DirEntry {
                name: name.into(),
                file_type: file_type.clone(),
                ino_info: get_node_info(&full_path),
            }
        }));
        Ok(entries)
    }

    fn file_status(&self, path: impl crate::path::Arg) -> Result<FileStatus, FileStatusError> {
        let path = self.absolute_path(path)?;
        let root = self.root.read();
        let (_, entry) = root.parent_and_entry(&path, self.current_user)?;
        let Some(entry) = entry else {
            return Err(PathError::NoSuchFileOrDirectory)?;
        };
        let (file_type, perms, size, unique_id) = match entry {
            Entry::File(file) => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                    file.unique_id,
                )
            }
            Entry::Dir(dir) => {
                let dir = dir.read();
                (
                    super::FileType::Directory,
                    dir.perms.clone(),
                    super::DEFAULT_DIRECTORY_SIZE,
                    dir.unique_id,
                )
            }
        };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
            owner: perms.userinfo,
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: unique_id,
                rdev: None,
            },
            blksize: BLOCK_SIZE,
        })
    }

    fn fd_file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let (file_type, perms, size, unique_id) = match &self
            .litebox
            .descriptor_table()
            .get_entry(fd)
            .ok_or(FileStatusError::ClosedFd)?
            .entry
        {
            Descriptor::File { file, .. } => {
                let file = file.read();
                (
                    super::FileType::RegularFile,
                    file.perms.clone(),
                    file.data.len(),
                    file.unique_id,
                )
            }
            Descriptor::Dir { dir, .. } => {
                let dir = dir.read();
                (
                    super::FileType::Directory,
                    dir.perms.clone(),
                    super::DEFAULT_DIRECTORY_SIZE,
                    dir.unique_id,
                )
            }
        };
        Ok(FileStatus {
            file_type,
            mode: perms.mode,
            size,
            owner: perms.userinfo,
            node_info: NodeInfo {
                dev: DEVICE_ID,
                ino: unique_id,
                rdev: None,
            },
            blksize: BLOCK_SIZE,
        })
    }

    fn get_static_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let descriptor_table = self.litebox.descriptor_table();
        let entry = descriptor_table.get_entry(fd)?;
        match &entry.entry {
            Descriptor::File { file, .. } => {
                let file = file.read();
                match &file.data {
                    alloc::borrow::Cow::Borrowed(slice) => Some(*slice),
                    alloc::borrow::Cow::Owned(_) => None,
                }
            }
            Descriptor::Dir { .. } => None,
        }
    }
}

struct RootDir<Platform: sync::RawSyncPrimitivesProvider> {
    // keys are normalized paths; directories do not have the final `/` (thus the root would be at
    // the empty-string key "")
    entries: HashMap<String, Entry<Platform>>,
}

// Parent, if it exists, is the path as well as the directory
//
// The entry, if it exists, is just the entry itself
type ParentAndEntry<'a, D, E> = Result<(Option<(&'a str, D)>, Option<E>), PathError>;

impl<Platform: sync::RawSyncPrimitivesProvider> RootDir<Platform> {
    fn new() -> Self {
        Self {
            entries: [(
                String::new(),
                Entry::Dir(Arc::new(sync::RwLock::new(DirX {
                    perms: Permissions {
                        mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                        userinfo: UserInfo { user: 0, group: 0 },
                    },
                    children: HashMap::default(),
                    unique_id: 0,
                }))),
            )]
            .into_iter()
            .collect(),
        }
    }

    fn parent_and_entry(
        &self,
        path: &str,
        current_user: UserInfo,
    ) -> ParentAndEntry<'_, Dir<Platform>, Entry<Platform>> {
        let mut real_components_seen = false;
        let mut collected = String::new();
        let mut parent_dir = None;
        for p in path.normalized_components()? {
            if p.is_empty() || p == ".." {
                // After normalization, these can only be at the start of the path, so can all be
                // ignored. We do an `assert` here mostly as a sanity check.
                assert!(!real_components_seen);
                continue;
            }
            // We have seen real components, should no longer see any empty or `/`s.
            real_components_seen = true;
            match self
                .entries
                .get_key_value(&collected)
                .ok_or(PathError::MissingComponent)?
            {
                (_, Entry::File(_)) => return Err(PathError::ComponentNotADirectory),
                (parent_path, Entry::Dir(dir)) => {
                    if !current_user.can_execute(&dir.read().perms) {
                        return Err(PathError::NoSearchPerms {
                            #[cfg(debug_assertions)]
                            dir: parent_path.clone(),
                            #[cfg(debug_assertions)]
                            perms: dir.read().perms.mode,
                        });
                    }
                    parent_dir = Some((parent_path.as_str(), dir.clone()));
                }
            }
            collected += "/";
            collected += p;
        }
        Ok((parent_dir, self.entries.get(&collected).cloned()))
    }
}

enum Entry<Platform: sync::RawSyncPrimitivesProvider> {
    File(File<Platform>),
    Dir(Dir<Platform>),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Entry<Platform> {
    fn perms(&self) -> Permissions {
        match self {
            Self::File(file) => file.read().perms.clone(),
            Self::Dir(dir) => dir.read().perms.clone(),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Entry<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
        }
    }
}

enum Node<Platform: sync::RawSyncPrimitivesProvider> {
    File(FileNode<Platform>),
    Dir(DirNode<Platform>),
}
impl<Platform: sync::RawSyncPrimitivesProvider> Clone for Node<Platform> {
    fn clone(&self) -> Self {
        match self {
            Self::File(file) => Self::File(file.clone()),
            Self::Dir(dir) => Self::Dir(dir.clone()),
        }
    }
}

type DirNode<Platform> = Arc<sync::RwLock<Platform, DirData<Platform>>>;
struct DirData<Platform: sync::RawSyncPrimitivesProvider> {
    perms: Permissions,
    children: HashMap<String, Node<Platform>>,
    node_info: NodeInfo,
}

type FileNode<Platform> = Arc<sync::RwLock<Platform, FileData>>;
struct FileData {
    perms: Permissions,
    data: alloc::borrow::Cow<'static, [u8]>,
    node_info: NodeInfo,
}

type Dir<Platform> = Arc<sync::RwLock<Platform, DirX>>;

pub(crate) struct DirX {
    perms: Permissions,
    children: HashMap<String, FileType>,
    unique_id: usize,
}

type File<Platform> = Arc<sync::RwLock<Platform, FileX>>;

pub(crate) struct FileX {
    perms: Permissions,
    data: alloc::borrow::Cow<'static, [u8]>,
    unique_id: usize,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

impl UserInfo {
    fn can_read(self, perms: &Permissions) -> bool {
        perms.can_read_by(self)
    }
    fn can_write(self, perms: &Permissions) -> bool {
        perms.can_write_by(self)
    }
    fn can_execute(self, perms: &Permissions) -> bool {
        perms.can_execute_by(self)
    }
}

impl Permissions {
    fn can_read_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::RUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::RGRP)
        } else {
            self.mode.contains(Mode::ROTH)
        }
    }
    fn can_write_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::WUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::WGRP)
        } else {
            self.mode.contains(Mode::WOTH)
        }
    }
    fn can_execute_by(&self, current: UserInfo) -> bool {
        if self.userinfo.user == current.user {
            self.mode.contains(Mode::XUSR)
        } else if self.userinfo.group == current.group {
            self.mode.contains(Mode::XGRP)
        } else {
            self.mode.contains(Mode::XOTH)
        }
    }
}

pub(crate) enum Descriptor<Platform: sync::RawSyncPrimitivesProvider> {
    File {
        file: File<Platform>,
        read_allowed: bool,
        write_allowed: bool,
        position: usize,
        append_mode: bool,
    },
    Dir {
        dir: Dir<Platform>,
    },
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    FileSystem<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Descriptor<Platform>;
    -> FileFd<Platform>;
}
