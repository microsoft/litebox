// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync;

use super::backend::{
    PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError,
    WalkError, WriteError,
};
use super::inode_allocator::InodeAllocator;
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, UserInfo};

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
    inode_allocator: InodeAllocator,
    // XXX(jayb): serializes directory moves so ancestry stays stable while rename chooses
    // ancestor-first locks; should be cleaned up as part of broader atomicity fixups.
    rename_lock: sync::Mutex<Platform, ()>,
}

impl<Platform: sync::RawSyncPrimitivesProvider> InMem<Platform> {
    fn resolved_dir<'a>(dir: InMemDirHandle<Platform>) -> ResolvedDir<'a> {
        let permissions = dir.dir.read().perms.permission_check();
        ResolvedDir::from_typed::<Self>(dir, permissions)
    }

    /// Construct a new `InMem` backend.
    #[must_use]
    pub fn new(inode_allocator: InodeAllocator) -> Self {
        let root = Arc::new(sync::RwLock::new(DirData {
            instance: Arc::new(()),
            perms: Permissions {
                mode: Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
                userinfo: UserInfo::ROOT,
            },
            children: HashMap::default(),
            node_info: inode_allocator.next(),
        }));
        Self {
            root,
            inode_allocator,
            rename_lock: sync::Mutex::new(()),
        }
    }

    /// Construct an `InMem` backend pre-populated with `entries`.
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
    ) -> Self {
        let this = Self::new(InodeAllocator::standalone());
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
                    instance: dir.instance.clone(),
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    children: HashMap::default(),
                    node_info: self.inode_allocator.next(),
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
                }));
                dir.children.insert(name.into(), Node::File(child));
            }
        }
    }

    fn contains_dir(ancestor: &DirNode<Platform>, target: &DirNode<Platform>) -> bool {
        let mut pending = alloc::vec![ancestor.clone()];
        while let Some(dir) = pending.pop() {
            if Arc::ptr_eq(&dir, target) {
                return true;
            }
            // Drop this read guard before visiting a descendant, or a rename's later write locks.
            pending.extend(dir.read().children.values().filter_map(|node| match node {
                Node::Dir(child) => Some(child.clone()),
                Node::File(_) => None,
            }));
        }
        false
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
    type ResolvedDir<'a> = InMemDirHandle<Platform>;
    type ResolvedFile<'a> = InMemFileHandle<Platform>;
    type FileHandle = InMemFileHandle<Platform>;
    type DirHandle = InMemDirHandle<Platform>;
}

impl<Platform: sync::RawSyncPrimitivesProvider> super::backend::Backend for InMem<Platform> {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(Self::resolved_dir(InMemDirHandle {
            dir: self.root.clone(),
            flags: super::OFlags::PATH,
        }))
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
            let child = dir.dir.read().children.get(*component).cloned();
            let Some(child) = child else {
                if index + 1 == components.len() {
                    return Ok(Resolution::MissingFinal {
                        parent: Self::resolved_dir(dir),
                    });
                }
                return Err(fail(PathError::NoSuchFileOrDirectory.into()));
            };
            match child {
                Node::Dir(child) => {
                    current = Self::resolved_dir(InMemDirHandle {
                        dir: child,
                        flags: super::OFlags::PATH,
                    });
                }
                Node::File(file) => {
                    if index + 1 != components.len() {
                        return Err(ResolutionError {
                            component: Some(index + 1),
                            error: PathError::ComponentNotADirectory.into(),
                        });
                    }
                    let (permissions, file_type) = {
                        let file = file.read();
                        (file.perms.permission_check(), file.file_type)
                    };
                    return Ok(Resolution::Found(ResolvedTarget::File(
                        ResolvedFile::from_typed::<Self>(
                            InMemFileHandle { file },
                            permissions,
                            file_type,
                        ),
                    )));
                }
            }
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(current)))
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        let dir = dir.get_typed::<Self>().dir.read();
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

    fn open_dir(
        &self,
        dir: ResolvedDir<'_>,
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

    fn walking_dir_at<'a>(&'a self, dir: &super::backend::DirHandle) -> Option<ResolvedDir<'a>> {
        Some(Self::resolved_dir(InMemDirHandle {
            dir: dir.get_typed::<Self>().dir.clone(),
            flags: super::OFlags::PATH,
        }))
    }

    fn open_file(
        &self,
        file: ResolvedFile<'_>,
        flags: super::OFlags,
    ) -> Result<super::backend::FileHandle, OpenError> {
        assert_supported_oflags(flags);
        if flags.contains(super::OFlags::DIRECTORY) {
            return Err(PathError::ComponentNotADirectory.into());
        }
        let handle = super::backend::FileHandle::from_typed::<Self>(file.into_typed::<Self>());
        if flags.contains(super::OFlags::TRUNC) && !flags.contains(super::OFlags::PATH) {
            // Linux truncates whenever the open succeeds, regardless of the access mode (an
            // `O_RDONLY|O_TRUNC` open of a writable file does truncate it); `O_PATH` opens ignore
            // `O_TRUNC` entirely.
            self.truncate(&handle, 0)?;
        }
        Ok(handle)
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
                    file_type: file.file_type,
                    mode: file.perms.mode,
                    size: u64::try_from(file.data.len()).map_err(|_| FileStatusError::Io)?,
                    owner: file.perms.userinfo,
                    node_info: file.node_info,
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
                    node_info: dir.node_info,
                    blksize: BLOCK_SIZE,
                })
            }
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        match target {
            ResolvedTarget::File(h) => self.status(super::backend::HandleRef::File(
                &super::backend::FileHandle::from_typed::<Self>(h.get_typed::<Self>().clone()),
            )),
            ResolvedTarget::Dir(h) => self.status(super::backend::HandleRef::Dir(
                &super::backend::DirHandle::from_typed::<Self>(h.get_typed::<Self>().clone()),
            )),
        }
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
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
        let file = Arc::new(sync::RwLock::new(FileData {
            perms: Permissions {
                mode: metadata.mode,
                userinfo: metadata.owner,
            },
            file_type: FileType::RegularFile,
            data: Vec::new().into(),
            node_info: self.inode_allocator.next(),
        }));
        let old = parent
            .children
            .insert(name.into(), Node::File(file.clone()));
        assert!(old.is_none());
        Ok(super::backend::FileHandle::from_typed::<Self>(
            InMemFileHandle { file },
        ))
    }

    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<(), SymlinkError> {
        let parent = dir.into_typed::<Self>();
        let mut parent = parent.dir.write();
        if parent.children.contains_key(name) {
            return Err(SymlinkError::AlreadyExists);
        }
        let file = Arc::new(sync::RwLock::new(FileData {
            perms: Permissions {
                mode: metadata.mode,
                userinfo: metadata.owner,
            },
            file_type: FileType::SymbolicLink,
            data: target.as_bytes().to_vec().into(),
            node_info: self.inode_allocator.next(),
        }));
        parent.children.insert(name.into(), Node::File(file));
        Ok(())
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
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
        let child = Arc::new(sync::RwLock::new(DirData {
            instance: parent.instance.clone(),
            perms: Permissions {
                mode: metadata.mode,
                userinfo: metadata.owner,
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

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
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

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
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

    fn rename_at(
        &self,
        old_dir: super::backend::DirHandle,
        old_name: &str,
        new_dir: super::backend::DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        for name in [old_name, new_name] {
            if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
                return Err(PathError::InvalidPathname.into());
            }
        }
        // XXX(jayb): racing rmdir can detach a resolved parent, as for create and mkdir; fix all
        // three together as part of broader atomicity fixups.
        let old_dir = old_dir.into_typed::<Self>().dir;
        let new_dir = new_dir.into_typed::<Self>().dir;
        let _rename = self.rename_lock.lock();
        let instance = self.root.read().instance.clone();
        let old_instance = old_dir.read().instance.clone();
        let new_instance = new_dir.read().instance.clone();
        if !Arc::ptr_eq(&old_instance, &instance) || !Arc::ptr_eq(&new_instance, &instance) {
            return Err(RenameError::Io);
        }
        let source = old_dir
            .read()
            .children
            .get(old_name)
            .cloned()
            .ok_or(PathError::NoSuchFileOrDirectory)?;
        let destination = new_dir.read().children.get(new_name).cloned();
        let same_parent = Arc::ptr_eq(&old_dir, &new_dir);
        let new_above_old = !same_parent && Self::contains_dir(&new_dir, &old_dir);
        let source_has_new = match &source {
            Node::Dir(dir) => Self::contains_dir(dir, &new_dir),
            Node::File(_) => false,
        };
        let destination_has_old = match &destination {
            Some(Node::Dir(dir)) if new_above_old => Self::contains_dir(dir, &old_dir),
            _ => false,
        };
        let replace = |old: &mut DirData<Platform>, new: Option<&mut DirData<Platform>>| {
            let current = old
                .children
                .get(old_name)
                .ok_or(PathError::NoSuchFileOrDirectory)?;
            let target = match &new {
                Some(new) => new.children.get(new_name),
                None => old.children.get(new_name),
            };
            if target.is_some_and(|target| current.ptr_eq(target)) {
                return Ok(());
            }
            // Ancestry was checked before locking, so it only holds for unchanged entries; a
            // concurrently created replacement cannot contain either existing parent.
            if source_has_new && current.ptr_eq(&source) {
                return Err(RenameError::InvalidArgument);
            }
            if let Some(target @ Node::Dir(dir)) = target
                && (Arc::ptr_eq(dir, &old_dir)
                    || (destination_has_old
                        && destination
                            .as_ref()
                            .is_some_and(|prior| target.ptr_eq(prior))))
            {
                return Err(RenameError::NotEmpty);
            }
            match (current, target) {
                (Node::Dir(_), Some(Node::File(_))) => return Err(RenameError::NotADirectory),
                (Node::File(_), Some(Node::Dir(_))) => return Err(RenameError::IsADirectory),
                (Node::Dir(_), Some(Node::Dir(dir))) if !dir.read().children.is_empty() => {
                    return Err(RenameError::NotEmpty);
                }
                _ => {}
            }
            let moved = old
                .children
                .remove(old_name)
                .expect("source was checked under lock");
            match new {
                Some(new) => new.children.insert(new_name.into(), moved),
                None => old.children.insert(new_name.into(), moved),
            };
            Ok(())
        };
        // XXX(jayb): nested directory locks are taken ancestor-first, with ancestry checked before
        // either write lock; revisit as part of broader atomicity fixups.
        if same_parent {
            replace(&mut old_dir.write(), None)
        } else if new_above_old {
            let mut new = new_dir.write();
            replace(&mut old_dir.write(), Some(&mut new))
        } else {
            let mut old = old_dir.write();
            replace(&mut old, Some(&mut new_dir.write()))
        }
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        let node = match h {
            ResolvedTarget::File(h) => Node::File(h.into_typed::<Self>().file),
            ResolvedTarget::Dir(h) => Node::Dir(h.into_typed::<Self>().dir),
        };
        let mut perms = match &node {
            Node::File(file) => {
                let file = file.write();
                if file.file_type == FileType::SymbolicLink {
                    return Err(ChmodError::IsSymlink);
                }
                sync::RwLockWriteGuard::map(file, |f| &mut f.perms)
            }
            Node::Dir(dir) => sync::RwLockWriteGuard::map(dir.write(), |d| &mut d.perms),
        };
        perms.mode = mode;
        Ok(())
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let node = match h {
            ResolvedTarget::File(h) => Node::File(h.into_typed::<Self>().file),
            ResolvedTarget::Dir(h) => Node::Dir(h.into_typed::<Self>().dir),
        };
        let mut perms = match &node {
            Node::File(file) => {
                let file = file.write();
                if file.file_type == FileType::SymbolicLink {
                    return Err(ChownError::IsSymlink);
                }
                sync::RwLockWriteGuard::map(file, |f| &mut f.perms)
            }
            Node::Dir(dir) => sync::RwLockWriteGuard::map(dir.write(), |d| &mut d.perms),
        };
        if let Some(new_user) = user {
            perms.userinfo.user = new_user;
        }
        if let Some(new_group) = group {
            perms.userinfo.group = new_group;
        }
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
    fn ptr_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Dir(left), Self::Dir(right)) => Arc::ptr_eq(left, right),
            (Self::File(left), Self::File(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

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
    instance: Arc<()>,
    perms: Permissions,
    children: HashMap<String, Node<Platform>>,
    node_info: NodeInfo,
}

type FileNode<Platform> = Arc<sync::RwLock<Platform, FileData>>;
struct FileData {
    perms: Permissions,
    file_type: FileType,
    /// The contents of a regular file, or the target of a symlink.
    data: alloc::borrow::Cow<'static, [u8]>,
    node_info: NodeInfo,
}

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

impl Permissions {
    fn permission_check(&self) -> PermissionCheck {
        PermissionCheck::ByResolver(PermissionInfo {
            mode: self.mode,
            owner: self.userinfo,
            on_read_only_fs: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::OFlags;
    use crate::fs::backend::Backend;
    use crate::fs::composer::Composer;
    use crate::fs::overlay::Overlay;
    use crate::fs::resolver::Resolver;
    use crate::test_platform::TestPlatform;
    use core::cell::RefCell;

    const OWNER: UserInfo = UserInfo {
        user: 1000,
        group: 1000,
    };
    const ALL: Mode = Mode::RWXU.union(Mode::RWXG).union(Mode::RWXO);

    #[test]
    fn mounted_ancestor_files_are_unreachable_without_mutation() {
        let backend = InMem::<TestPlatform>::new_initialized([
            (
                "/a",
                InitialNode::File {
                    mode: ALL,
                    owner: OWNER,
                    data: b"preserve".as_slice().into(),
                },
            ),
            (
                "/target",
                InitialNode::File {
                    mode: ALL,
                    owner: OWNER,
                    data: b"target".as_slice().into(),
                },
            ),
            (
                "/link",
                InitialNode::Symlink {
                    mode: ALL,
                    owner: OWNER,
                    target: "/target".into(),
                },
            ),
        ]);
        let backing_file = match backend.root.read().children.get("a").unwrap() {
            Node::File(file) => file.clone(),
            Node::Dir(_) => panic!("expected backing file"),
        };
        let composer = Composer::builder()
            .mount("/", |_| backend)
            .mount("/a/b", InMem::<TestPlatform>::new)
            .mount("/link/child", InMem::<TestPlatform>::new)
            .build()
            .unwrap();
        assert!(matches!(
            composer.resolve(composer.root().unwrap(), &["a"], &|_| Ok(())),
            Err(ResolutionError {
                component: Some(0),
                error: WalkError::PathError(PathError::NoSuchFileOrDirectory),
            })
        ));
        let fs = Resolver::<TestPlatform, _>::new(composer);
        for flags in [
            OFlags::WRONLY | OFlags::TRUNC,
            OFlags::CREAT | OFlags::WRONLY,
        ] {
            assert!(matches!(
                fs.open(OWNER, "/a", flags, ALL),
                Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
            ));
        }
        assert_eq!(backing_file.read().data.as_ref(), b"preserve");
        let fd = fs
            .open(OWNER, "/link", OFlags::RDONLY, Mode::empty())
            .unwrap();
        assert_eq!(fd.path(), "/target");
        assert_eq!(fs.read_link(OWNER, "/link").unwrap(), "/target");
    }

    #[test]
    fn denied_overlay_mutations_do_not_copy_up_or_materialize_ancestors() {
        let upper = InMem::<TestPlatform>::new(InodeAllocator::standalone());
        let upper_root = upper.root.clone();
        let lower = InMem::<TestPlatform>::new_initialized([
            (
                "/a",
                InitialNode::Directory {
                    mode: ALL,
                    owner: OWNER,
                },
            ),
            (
                "/a/b",
                InitialNode::Directory {
                    mode: ALL,
                    owner: OWNER,
                },
            ),
            (
                "/a/b/file",
                InitialNode::File {
                    mode: Mode::RUSR | Mode::WUSR | Mode::ROTH,
                    owner: OWNER,
                    data: b"keep lower".as_slice().into(),
                },
            ),
        ]);
        let overlay = Overlay::<TestPlatform>::new(upper, lower, InodeAllocator::standalone());
        let backend = Composer::builder()
            .mount("/mnt", |_| overlay)
            .build()
            .unwrap();
        let fs = Resolver::<TestPlatform, _>::new(backend);
        let other_user = UserInfo {
            user: 2000,
            group: 2000,
        };
        for flags in [
            OFlags::WRONLY,
            OFlags::WRONLY | OFlags::TRUNC,
            OFlags::RDWR | OFlags::TRUNC,
        ] {
            assert!(matches!(
                fs.open(other_user, "/mnt/a/b/file", flags, Mode::empty()),
                Err(OpenError::AccessNotAllowed)
            ));
            assert!(upper_root.read().children.is_empty());
        }
        assert!(matches!(
            fs.chmod(other_user, "/mnt/a/b/file", ALL),
            Err(ChmodError::NotTheOwner)
        ));
        assert!(upper_root.read().children.is_empty());
        assert!(matches!(
            fs.chown(other_user, "/mnt/a/b/file", Some(2000), None),
            Err(ChownError::NotTheOwner)
        ));
        assert!(upper_root.read().children.is_empty());
        let fd = fs
            .open(
                other_user,
                "/mnt/a/b/file",
                OFlags::PATH | OFlags::WRONLY | OFlags::TRUNC,
                Mode::empty(),
            )
            .unwrap();
        assert_eq!(fs.handle_status(&fd).unwrap().size, 10);
        drop(fd);
        assert!(upper_root.read().children.is_empty());
        let mut fd = fs
            .open(other_user, "/mnt/a/b/file", OFlags::RDONLY, Mode::empty())
            .unwrap();
        let mut buf = [0; 32];
        let count = fs.read(&mut fd, &mut buf, None).unwrap();
        assert_eq!(&buf[..count], b"keep lower");
        drop(fd);
        assert!(upper_root.read().children.is_empty());
        let fd = fs
            .open(
                OWNER,
                "/mnt/a/b/file",
                OFlags::WRONLY | OFlags::TRUNC,
                Mode::empty(),
            )
            .unwrap();
        assert_eq!(fs.handle_status(&fd).unwrap().size, 0);
        drop(fd);
        assert!(upper_root.read().children.contains_key("a"));
    }

    #[test]
    fn root_and_final_directory_authorization_are_distinct_from_search() {
        let backend = InMem::<TestPlatform>::new_initialized([
            (
                "/",
                InitialNode::Directory {
                    mode: Mode::RUSR,
                    owner: OWNER,
                },
            ),
            (
                "/dir",
                InitialNode::Directory {
                    mode: Mode::RUSR,
                    owner: OWNER,
                },
            ),
        ]);
        let fs = Resolver::<TestPlatform, _>::new(backend);
        let fd = fs.open(OWNER, "/", OFlags::RDONLY, Mode::empty()).unwrap();
        drop(fd);
        assert!(matches!(
            fs.open(OWNER, "/absent", OFlags::PATH, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSearchPerms))
        ));
        fs.chmod(OWNER, "/", Mode::RUSR | Mode::XUSR).unwrap();
        let fd = fs
            .open(OWNER, "/dir", OFlags::RDONLY, Mode::empty())
            .unwrap();
        drop(fd);
        assert!(matches!(
            fs.open(OWNER, "/dir/absent", OFlags::PATH, Mode::empty()),
            Err(OpenError::PathError(PathError::NoSearchPerms))
        ));
        let other_user = UserInfo {
            user: 2000,
            group: 2000,
        };
        assert!(matches!(
            fs.open(other_user, "/", OFlags::RDONLY, Mode::empty()),
            Err(OpenError::AccessNotAllowed)
        ));
        let fd = fs
            .open(other_user, "/", OFlags::PATH, Mode::empty())
            .unwrap();
        drop(fd);
        fs.file_status(other_user, "/", true).unwrap();
    }

    #[test]
    fn lookup_authorization_precedes_missing_and_target_metadata() {
        let backend = InMem::<TestPlatform>::new_initialized([
            (
                "/dir",
                InitialNode::Directory {
                    mode: Mode::RUSR,
                    owner: OWNER,
                },
            ),
            (
                "/dir/file",
                InitialNode::File {
                    mode: Mode::WUSR,
                    owner: OWNER,
                    data: b"keep".as_slice().into(),
                },
            ),
        ]);
        for components in [
            &["dir", "missing"][..],
            &["dir", "missing", "child"],
            &["dir", "file"],
            &["dir", "file", "child"],
        ] {
            let calls = RefCell::new(Vec::new());
            let result = backend.resolve(backend.root().unwrap(), components, &|permissions| {
                calls
                    .borrow_mut()
                    .push((permissions.mode, permissions.owner));
                if permissions.owner == OWNER {
                    Err(PathError::NoSearchPerms.into())
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(ResolutionError {
                    component: Some(1),
                    error: WalkError::PathError(PathError::NoSearchPerms),
                })
            ));
            assert_eq!(calls.borrow().len(), 2);
            assert_eq!(calls.borrow()[1], (Mode::RUSR, OWNER));
        }

        assert!(matches!(
            backend.resolve(backend.root().unwrap(), &["dir", "missing"], &|_| Ok(())),
            Ok(Resolution::MissingFinal { .. })
        ));
        assert!(matches!(
            backend.resolve(
                backend.root().unwrap(),
                &["dir", "missing", "child"],
                &|_| Ok(())
            ),
            Err(ResolutionError {
                component: Some(1),
                error: WalkError::PathError(PathError::NoSuchFileOrDirectory),
            })
        ));
        assert!(matches!(
            backend.resolve(backend.root().unwrap(), &["dir", "file", "child"], &|_| Ok(
                ()
            )),
            Err(ResolutionError {
                component: Some(2),
                error: WalkError::PathError(PathError::ComponentNotADirectory),
            })
        ));
    }
}
