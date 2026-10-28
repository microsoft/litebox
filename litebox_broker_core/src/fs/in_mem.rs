// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SetTimesError, TruncateError, UnlinkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{
    DirEntry, FileStatus, FileTime, FileType, Mode, NodeInfo, TimeUpdate, UserInfo,
    WallClockProvider,
};

/// A [`super::backend::Backend`] that stores all files in memory.
///
/// Objects are stamped with times from a [`WallClockProvider`]; reading a file does not update its
/// access time.
///
/// # Warning
///
/// This has no physical backing store, thus any files in memory are erased as soon as this object
/// is dropped.
pub struct InMem<Platform: sync::RawSyncPrimitivesProvider> {
    // TODO: Possibly support a single-threaded variant that doesn't have the cost of requiring a
    // sync-primitives platform, as well as cost of mutexes and such?
    root: DirNode<Platform>,
    inode_allocator: InodeAllocator,
    clock: Arc<dyn WallClockProvider>,
}

impl<Platform: sync::RawSyncPrimitivesProvider> InMem<Platform> {
    /// Construct a new `InMem` backend, whose objects are stamped with times from `clock`.
    #[must_use]
    pub fn new(inode_allocator: InodeAllocator, clock: Arc<dyn WallClockProvider>) -> Self {
        let root = Arc::new(sync::RwLock::new(DirData {
            perms: Permissions {
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                userinfo: UserInfo::ROOT,
            },
            children: HashMap::default(),
            node_info: inode_allocator.next(),
            times: Times::new(clock.now()),
        }));
        Self {
            root,
            inode_allocator,
            clock,
        }
    }

    /// Construct an `InMem` backend pre-populated with `entries`, whose objects are stamped with
    /// times from `clock`.
    ///
    /// Entries are inserted in order, bypassing all permission checks, which is what lets a caller
    /// set up root-owned directories and files without ever acting as root at runtime. Each
    /// entry's parent must already exist, either as the root or from an earlier entry;
    /// re-specifying an existing path updates its mode and owner (and, for a file, its contents
    /// or symlink target), which is how the root directory's own permissions are set (via `/`).
    ///
    /// # Panics
    ///
    /// Panics if an entry's parent does not exist or is not a directory, if an entry changes the
    /// type of an existing path, if the root is given as a non-directory, or if a symlink target
    /// is malformed.
    #[must_use]
    pub fn new_initialized<Path: AsRef<str>>(
        entries: impl IntoIterator<Item = (Path, impl Into<InitialNode>)>,
        clock: Arc<dyn WallClockProvider>,
    ) -> Self {
        let this = Self::new(InodeAllocator::standalone(), clock);
        for (path, node) in entries {
            this.insert_initial(path.as_ref(), node.into());
        }
        this
    }

    /// Insert a single [`InitialNode`], as described on [`Self::new_initialized`].
    fn insert_initial(&self, path: &str, node: InitialNode) {
        if let InitialNode::Symlink { mode, target, .. } = &node {
            assert!(
                !target.is_empty() && !target.as_bytes().contains(&0),
                "symlink targets must be nonempty and contain no NUL bytes"
            );
            if *mode != Mode::RWXU | Mode::RWXG | Mode::RWXO {
                litebox_util_log::debug!(
                    path:? = path, mode:? = mode;
                    "symlink modes other than 0777 may not be fully supported"
                );
            }
        }
        let mut components = path.split('/').filter(|component| {
            assert!(
                !matches!(*component, "." | ".."),
                "initial paths must be normalized, got {path:?}"
            );
            !component.is_empty()
        });
        let Some(mut name) = components.next() else {
            // The path is the root itself, which already exists, so only its permissions apply.
            let InitialNode::Directory { mode, owner } = node else {
                panic!("the root directory must be initialized as a directory")
            };
            self.root.write().perms = Permissions {
                mode,
                userinfo: owner,
            };
            return;
        };

        let mut dir = self.root.clone();
        for next in components {
            let child = dir
                .read()
                .children
                .get(name)
                .unwrap_or_else(|| panic!("missing parent directory for {path:?}"))
                .clone();
            let Node::Dir(child) = child else {
                panic!("parent of {path:?} is not a directory")
            };
            dir = child;
            name = next;
        }

        let mut dir = dir.write();
        let now = self.clock.now();
        if !dir.children.contains_key(name) {
            dir.times.modify(now);
        }
        match (dir.children.get(name), node) {
            (Some(Node::Dir(existing)), InitialNode::Directory { mode, owner }) => {
                existing.write().perms = Permissions {
                    mode,
                    userinfo: owner,
                };
            }
            (Some(Node::File(existing)), InitialNode::File { mode, owner, data }) => {
                let mut existing = existing.write();
                assert_eq!(
                    existing.file_type,
                    FileType::RegularFile,
                    "{path:?} already exists with a different type"
                );
                existing.perms = Permissions {
                    mode,
                    userinfo: owner,
                };
                existing.data = data;
            }
            (
                Some(Node::File(existing)),
                InitialNode::Symlink {
                    mode,
                    owner,
                    target,
                },
            ) => {
                let mut existing = existing.write();
                assert_eq!(
                    existing.file_type,
                    FileType::SymbolicLink,
                    "{path:?} already exists with a different type"
                );
                existing.perms = Permissions {
                    mode,
                    userinfo: owner,
                };
                existing.data = target.into_bytes().into();
            }
            (Some(_), _) => panic!("{path:?} already exists with a different type"),
            (None, InitialNode::Directory { mode, owner }) => {
                let child = Arc::new(sync::RwLock::new(DirData {
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    children: HashMap::default(),
                    node_info: self.inode_allocator.next(),
                    times: Times::new(now),
                }));
                dir.children.insert(name.into(), Node::Dir(child));
            }
            (None, InitialNode::File { mode, owner, data }) => {
                let child = Arc::new(sync::RwLock::new(FileData {
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    file_type: FileType::RegularFile,
                    data,
                    node_info: self.inode_allocator.next(),
                    times: Times::new(now),
                }));
                dir.children.insert(name.into(), Node::File(child));
            }
            (
                None,
                InitialNode::Symlink {
                    mode,
                    owner,
                    target,
                },
            ) => {
                let child = Arc::new(sync::RwLock::new(FileData {
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    file_type: FileType::SymbolicLink,
                    data: target.into_bytes().into(),
                    node_info: self.inode_allocator.next(),
                    times: Times::new(now),
                }));
                dir.children.insert(name.into(), Node::File(child));
            }
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
    /// Panics if used on a symlink or a file that already contains data.
    pub fn initialize_primarily_read_heavy_file(
        &self,
        h: &super::backend::FileHandle,
        data: alloc::borrow::Cow<'static, [u8]>,
    ) {
        let mut file = h.get_typed::<Self>().file.write();
        assert_eq!(
            file.file_type,
            FileType::RegularFile,
            "must only be used on regular files during initialization"
        );
        assert!(
            file.data.is_empty(),
            "must only be used on empty files during initialization"
        );
        file.data = data;
    }

    /// Apply `update` to the permissions of the non-symlink object `h` refers to, failing with
    /// `symlink_error` for a symlink, and stamp its status change time.
    fn change_permissions<E>(
        &self,
        h: super::backend::HandleRef<'_>,
        symlink_error: E,
        update: impl FnOnce(&mut Permissions),
    ) -> Result<(), E> {
        match h {
            super::backend::HandleRef::File(h) => {
                let mut file = h.get_typed::<Self>().file.write();
                if file.file_type == FileType::SymbolicLink {
                    return Err(symlink_error);
                }
                update(&mut file.perms);
                file.times.changed = self.clock.now();
            }
            super::backend::HandleRef::Dir(h) => {
                let mut dir = h.get_typed::<Self>().dir.write();
                update(&mut dir.perms);
                dir.times.changed = self.clock.now();
            }
        }
        Ok(())
    }
}

/// A node used to pre-populate an [`InMem`] backend, via [`InMem::new_initialized`].
pub enum InitialNode {
    /// A directory.
    Directory {
        /// Permission bits for the directory.
        mode: Mode,
        /// Owning user and group.
        owner: UserInfo,
    },
    /// A regular file, along with its contents.
    File {
        /// Permission bits for the file.
        mode: Mode,
        /// Owning user and group.
        owner: UserInfo,
        /// The file's contents.
        ///
        /// Borrowed data is kept borrowed until the first write to the file, which makes this the
        /// cheap way to set up large read-heavy files (such as executables).
        data: alloc::borrow::Cow<'static, [u8]>,
    },
    /// A symbolic link.
    Symlink {
        /// Permission bits for the link.
        mode: Mode,
        /// Owning user and group.
        owner: UserInfo,
        /// The link's target; it need not exist or be normalized.
        target: String,
    },
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
            let child = match child {
                Node::Dir(child) => child,
                Node::File(file) => {
                    return Ok(super::backend::WalkOutcome {
                        components: walked_components,
                        last: super::backend::WalkingDirHandle::from_typed::<Self>(current),
                        stop_reason: super::backend::WalkStopReason::StoppedAtNonDirectory {
                            file_type: file.read().file_type,
                        },
                    });
                }
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

    fn read_link_at(
        &self,
        dir: &super::backend::WalkingDirHandle<'_>,
        name: &str,
    ) -> Result<String, super::errors::WalkError> {
        let dir = dir.as_typed::<Self>().dir.read();
        let file = match dir.children.get(name) {
            Some(Node::File(file)) => file.read(),
            Some(Node::Dir(_)) => return Err(PathError::InvalidPathname.into()),
            None => return Err(PathError::NoSuchFileOrDirectory.into()),
        };
        if file.file_type != FileType::SymbolicLink {
            return Err(PathError::InvalidPathname.into());
        }
        Ok(core::str::from_utf8(&file.data)
            .expect("symlink targets are initialized from strings")
            .into())
    }

    fn owned_dir_at(
        &self,
        dir: super::backend::WalkingDirHandle<'_>,
        flags: super::OFlags,
    ) -> Result<super::backend::DirHandle, OpenError> {
        assert_supported_oflags(flags);
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
            .map(|(name, child)| child.dir_entry(name))
            .collect())
    }

    fn lookup_at(
        &self,
        dir: &super::backend::DirHandle,
        name: &str,
    ) -> Result<Option<DirEntry>, ReadDirError> {
        Ok(dir
            .get_typed::<Self>()
            .dir
            .read()
            .children
            .get_key_value(name)
            .map(|(name, child)| child.dir_entry(name)))
    }

    fn read(
        &self,
        h: &super::backend::FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let file = h.get_typed::<Self>().file.read();
        let start = offset.min(file.data.len());
        let end = offset.checked_add(buf.len()).unwrap().min(file.data.len());
        debug_assert!(start <= end);
        let len = end - start;
        buf.copy_from_slice_at(0, &file.data[start..end])?;
        Ok(len)
    }

    fn write(
        &self,
        h: &super::backend::FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let mut file = h.get_typed::<Self>().file.write();
        let data = file.data.to_mut();
        let previous_len = data.len();
        let end = offset.checked_add(buf.len()).unwrap();
        if end > previous_len {
            // Pads with 0s if the offset is past the end of the file.
            data.resize(end, 0);
        }
        if let Err(fault) = buf.copy_to_slice_at(0, &mut data[offset..end]) {
            data.truncate(previous_len);
            return Err(fault.into());
        }
        if !buf.is_empty() {
            file.times.modify(self.clock.now());
        }
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
        // Like Linux's `ftruncate` and `O_TRUNC`, even a truncation to the current size counts.
        file.times.modify(self.clock.now());
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
                    file_type: file.file_type,
                    mode: file.perms.mode,
                    size: u64::try_from(file.data.len()).map_err(|_| FileStatusError::Io)?,
                    owner: file.perms.userinfo,
                    node_info: file.node_info,
                    blksize: BLOCK_SIZE,
                    accessed: file.times.accessed,
                    modified: file.times.modified,
                    changed: file.times.changed,
                })
            }
            super::backend::HandleRef::Dir(h) => {
                let dir = h.get_typed::<Self>().dir.read();
                Ok(FileStatus {
                    file_type: FileType::Directory,
                    mode: dir.perms.mode,
                    size: super::DEFAULT_DIRECTORY_SIZE,
                    owner: dir.perms.userinfo,
                    node_info: dir.node_info,
                    blksize: BLOCK_SIZE,
                    accessed: dir.times.accessed,
                    modified: dir.times.modified,
                    changed: dir.times.changed,
                })
            }
        }
    }

    fn create_file_at(
        &self,
        dir: super::backend::DirHandle,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<super::backend::FileHandle, OpenError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before creating;
        // the resolver should do so before calling this.
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        if parent.children.contains_key(name) {
            return Err(OpenError::AlreadyExists);
        }
        let now = self.clock.now();
        let file = Arc::new(sync::RwLock::new(FileData {
            perms: Permissions {
                mode: metadata.mode,
                userinfo: metadata.owner,
            },
            file_type: FileType::RegularFile,
            data: Vec::new().into(),
            node_info: self.inode_allocator.next(),
            times: Times::new(now),
        }));
        parent.times.modify(now);
        let old = parent
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
        metadata: super::backend::CreationMetadata,
    ) -> Result<super::backend::DirHandle, MkdirError> {
        // TODO(jayb): Nothing checks write permission on the parent directory before creating;
        // the resolver should do so before calling this.
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        if parent.children.contains_key(name) {
            return Err(MkdirError::AlreadyExists);
        }
        let now = self.clock.now();
        let child = Arc::new(sync::RwLock::new(DirData {
            perms: Permissions {
                mode: metadata.mode,
                userinfo: metadata.owner,
            },
            children: HashMap::default(),
            node_info: self.inode_allocator.next(),
            times: Times::new(now),
        }));
        parent.times.modify(now);
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
            Some(Node::File(file)) => {
                // Its link count changed, which open handles can still observe.
                let mut file = file.write();
                let now = self.clock.now();
                file.times.changed = now;
                drop(file);
                parent.children.remove(name);
                parent.times.modify(now);
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
            Some(Node::Dir(child)) => {
                // Its link count changed, which open handles can still observe.
                let mut child = child.write();
                let now = self.clock.now();
                child.times.changed = now;
                drop(child);
                parent.children.remove(name);
                parent.times.modify(now);
                Ok(())
            }
        }
    }

    fn chmod(&self, h: super::backend::HandleRef<'_>, mode: Mode) -> Result<(), ChmodError> {
        self.change_permissions(h, ChmodError::IsSymlink, |perms| perms.mode = mode)
    }

    fn chown(
        &self,
        h: super::backend::HandleRef<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.change_permissions(h, ChownError::IsSymlink, |perms| {
            if let Some(new_user) = user {
                perms.userinfo.user = new_user;
            }
            if let Some(new_group) = group {
                perms.userinfo.group = new_group;
            }
        })
    }

    fn set_times(
        &self,
        h: super::backend::HandleRef<'_>,
        accessed: TimeUpdate,
        modified: TimeUpdate,
    ) -> Result<(), SetTimesError> {
        let mut times = match h {
            super::backend::HandleRef::File(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().file.write(), |f| &mut f.times)
            }
            super::backend::HandleRef::Dir(h) => {
                sync::RwLockWriteGuard::map(h.get_typed::<Self>().dir.write(), |d| &mut d.times)
            }
        };
        times.update(accessed, modified, self.clock.now());
        Ok(())
    }

    fn get_static_backing_data(&self, h: &super::backend::FileHandle) -> Option<&'static [u8]> {
        let file = h.get_typed::<Self>().file.read();
        if file.file_type == FileType::SymbolicLink {
            return None;
        }
        match file.data {
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

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: u64 = 0;

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

impl<Platform: sync::RawSyncPrimitivesProvider> Node<Platform> {
    /// The directory entry for this node, named `name` in its parent.
    fn dir_entry(&self, name: &str) -> DirEntry {
        let (file_type, node_info) = match self {
            Node::File(file) => {
                let file = file.read();
                (file.file_type, file.node_info)
            }
            Node::Dir(dir) => (FileType::Directory, dir.read().node_info),
        };
        DirEntry {
            name: name.into(),
            file_type,
            ino_info: Some(node_info),
        }
    }
}

type DirNode<Platform> = Arc<sync::RwLock<Platform, DirData<Platform>>>;
struct DirData<Platform: sync::RawSyncPrimitivesProvider> {
    perms: Permissions,
    children: HashMap<String, Node<Platform>>,
    node_info: NodeInfo,
    times: Times,
}

type FileNode<Platform> = Arc<sync::RwLock<Platform, FileData>>;
struct FileData {
    perms: Permissions,
    file_type: FileType,
    /// The contents of a regular file, or the target of a symlink.
    data: alloc::borrow::Cow<'static, [u8]>,
    node_info: NodeInfo,
    times: Times,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

#[derive(Clone, Copy, Debug)]
struct Times {
    accessed: FileTime,
    modified: FileTime,
    changed: FileTime,
}

impl Times {
    /// The times of an object created at `now`.
    fn new(now: FileTime) -> Self {
        Self {
            accessed: now,
            modified: now,
            changed: now,
        }
    }

    /// Record a change, at `now`, to a file's data or a directory's entries.
    fn modify(&mut self, now: FileTime) {
        self.modified = now;
        self.changed = now;
    }

    /// Apply a [`super::backend::Backend::set_times`] at `now`.
    fn update(&mut self, accessed: TimeUpdate, modified: TimeUpdate, now: FileTime) {
        if (accessed, modified) == (TimeUpdate::Omit, TimeUpdate::Omit) {
            return;
        }
        let resolve = |update, current| match update {
            TimeUpdate::Omit => current,
            TimeUpdate::Now => now,
            TimeUpdate::Set(time) => time,
        };
        self.accessed = resolve(accessed, self.accessed);
        self.modified = resolve(modified, self.modified);
        self.changed = now;
    }
}
