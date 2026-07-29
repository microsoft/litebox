// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! An in-memory file system, not backed by any physical device.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use hashbrown::HashMap;

use crate::sync;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, TruncateError, UnlinkError, WriteError,
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
    // TODO(jayb): This duplicates the resolver's `Context::user_info`, which is supposed to own
    // this. This exists as a transition until we update callers to either manage the perm checks or
    // pass down the UserInfo.
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

    /// Construct an `InMem` backend pre-populated with `entries`.
    ///
    /// Entries are inserted in order, bypassing all permission checks, which is what lets a caller
    /// set up root-owned directories and files without ever acting as root at runtime. Each
    /// entry's parent must already exist, either as the root or from an earlier entry;
    /// re-specifying an existing path updates its mode and owner (and, for a file, its contents),
    /// which is how the root directory's own permissions are set (via the path `/`).
    ///
    /// # Panics
    ///
    /// Panics if an entry's parent does not exist or is not a directory, if an entry changes the
    /// type of an existing path, or if the root is given as a file.
    #[must_use]
    pub fn new_initialized<Path: AsRef<str>>(
        entries: impl IntoIterator<Item = (Path, InitialNode)>,
    ) -> Self {
        let this = Self::new(InodeAllocator::standalone());
        for (path, node) in entries {
            this.insert_initial(path.as_ref(), node);
        }
        this
    }

    /// Insert a single [`InitialNode`], as described on [`Self::new_initialized`].
    fn insert_initial(&self, path: &str, node: InitialNode) {
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
                panic!("the root directory cannot be initialized as a file")
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
                existing.perms = Permissions {
                    mode,
                    userinfo: owner,
                };
                existing.data = data;
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
                }));
                dir.children.insert(name.into(), Node::Dir(child));
            }
            (None, InitialNode::File { mode, owner, data }) => {
                let child = Arc::new(sync::RwLock::new(FileData {
                    perms: Permissions {
                        mode,
                        userinfo: owner,
                    },
                    data,
                    node_info: self.inode_allocator.next(),
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

/// Block size for file system I/O operations
// TODO(jayb): Determine appropriate block size
const BLOCK_SIZE: usize = 0;

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

#[derive(Clone, Debug)]
struct Permissions {
    mode: Mode,
    userinfo: UserInfo,
}

/// Run `f` with the acting user set to root.
///
/// Non-test callers set up root-owned state via [`InMem::new_initialized`] instead; this exists so
/// that the tests can exercise operations that depend on the acting user.
#[cfg(test)]
pub(super) fn with_root_privileges<Platform: sync::RawSyncPrimitivesProvider>(
    fs: &mut super::resolver::Resolver<Platform, InMem<Platform>>,
    f: impl FnOnce(&mut super::resolver::Resolver<Platform, InMem<Platform>>),
) {
    with_user(fs, UserInfo::ROOT.user, UserInfo::ROOT.group, f);
}

/// Run `f` with the acting user set to `user`/`group`. See [`with_root_privileges`].
#[cfg(test)]
pub(super) fn with_user<Platform: sync::RawSyncPrimitivesProvider>(
    fs: &mut super::resolver::Resolver<Platform, InMem<Platform>>,
    user: u16,
    group: u16,
    f: impl FnOnce(&mut super::resolver::Resolver<Platform, InMem<Platform>>),
) {
    let user = UserInfo { user, group };
    let original_user = fs.swap_acting_user(user);
    fs.backend_mut().current_user = user;
    f(fs);
    let user_again = fs.swap_acting_user(original_user);
    fs.backend_mut().current_user = original_user;
    assert!(user_again.user == user.user && user_again.group == user.group);
}
