// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A file system on a FUSE server, such as `virtiofsd` behind a virtio-fs device.
//!
//! The server's node ids (counted lookups, to be forgotten) and open handles (to be released) are
//! dropped with their last reference, as [`Backend`](super::backend::Backend) has no close hook.
//! Lookups are of single names, so the server never follows a symlink: the resolver expands them
//! in the guest's namespace. As the userland broker's host files, special files are hidden: the
//! broker has no use for them, and their server-side opens would block (FIFOs) or reach the host's
//! drivers (devices).
//!
//! As with Linux's dentries, a directory's `..` is where the client last found it, never asked of
//! the server (`virtiofsd` resolves `..` within the directory itself): the host's moves show once a
//! lookup or a listing finds them.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use super::OFlags;
use super::backend::Caller;
use super::backend::{
    DirHandle, FileHandle, HandleRef, PermissionCheck, PermissionInfo, Resolution, ResolvedDir,
    ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SetTimesError, SymlinkError,
    TruncateError, UnlinkError, WalkError, WriteError,
};
use litebox_platform::buffer::{Fault, ReadBuffer, WriteBuffer};
use litebox_platform::sync;
use litebox_platform::sync::{Mutex, MutexGuard};

use crate::BrokerError;

mod abi;
mod client;
#[cfg(all(test, target_os = "linux"))]
mod tests;

pub mod transport;

/// A [`Backend`](super::backend::Backend) backed by a FUSE server.
///
/// As with the userland broker's host files, the server enforces permissions
/// ([`PermissionCheck::ByBackend`]) and creates files as whoever runs it, and the guest makes no
/// setuid or setgid files.
///
/// Every file reports this backend's one device id with the server's inode number, so an export
/// spanning several host file systems (submounts are not negotiated) may report the same (device,
/// inode) pair, which also keys `flock`s, for distinct files: export those as separate shares.
pub struct Fuse<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    client: Arc<client::Client<Platform, T>>,
    root: Arc<Node<Platform, T>>,
    /// Held across each request that finds or changes names and the parents it updates, and while
    /// reading a parent: with one request at a time, parents change in the server's order.
    namespace: Mutex<Platform, ()>,
    dirs: Arc<Dirs<Platform, T>>,
    device_id: u64,
}

/// The live directories' nodes, one per node id, as Linux keeps one dentry per directory.
type Dirs<Platform, T> = Mutex<Platform, BTreeMap<u64, Weak<Node<Platform, T>>>>;

/// The namespace lock, held.
type Namespace<'a, Platform> = MutexGuard<'a, Platform, ()>;

enum Found<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    Dir(Arc<Node<Platform, T>>, abi::Attr),
    /// Counted, for the caller to own or forget.
    Other(abi::EntryOut),
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Fuse<Platform, T> {
    /// Negotiates the protocol with the server (`FUSE_INIT`).
    pub fn new(
        transport: T,
        inode_allocator: super::inode_allocator::InodeAllocator,
    ) -> Result<Self, Error> {
        let client = Arc::new(client::Client::new(transport)?);
        Ok(Self {
            root: Arc::new(Node {
                id: abi::ROOT_ID,
                lookups: AtomicU64::new(0),
                file_type: abi::S_IFDIR,
                parent: Mutex::new(None),
                dirs: None,
                client: Arc::clone(&client),
            }),
            namespace: Mutex::new(()),
            dirs: Arc::new(Mutex::new(BTreeMap::new())),
            client,
            device_id: inode_allocator.device_id(),
        })
    }

    /// The node of the non-directory `entry`, whose lookup the server just counted.
    fn own_file(&self, entry: &abi::EntryOut) -> Arc<Node<Platform, T>> {
        Arc::new(Node {
            id: entry.nodeid,
            lookups: AtomicU64::new(1),
            file_type: entry.attr.file_type(),
            parent: Mutex::new(None),
            dirs: None,
            client: Arc::clone(&self.client),
        })
    }

    /// `name` in `dir`; a directory through [`Self::dir_node`].
    fn lookup(
        &self,
        namespace: &Namespace<'_, Platform>,
        dir: &Arc<Node<Platform, T>>,
        name: &str,
    ) -> Result<Found<Platform, T>, Error> {
        let entry = self.client.lookup(dir.id, name)?;
        if entry.attr.is_dir() {
            let node = self.dir_node(namespace, &entry, dir)?;
            Ok(Found::Dir(node, entry.attr))
        } else {
            Ok(Found::Other(entry))
        }
    }

    /// The directory `name` in `dir`; none if it is no directory.
    fn dir_at(
        &self,
        namespace: &Namespace<'_, Platform>,
        dir: &Arc<Node<Platform, T>>,
        name: &str,
    ) -> Result<Option<Arc<Node<Platform, T>>>, Error> {
        match self.lookup(namespace, dir, name)? {
            Found::Dir(node, _) => Ok(Some(node)),
            Found::Other(entry) => {
                self.client.forget(entry.nodeid, 1);
                Ok(None)
            }
        }
    }

    /// The node of the directory `entry`, whose lookup in `parent` the server just counted: the live
    /// one, moved there, else a new one.
    fn dir_node(
        &self,
        namespace: &Namespace<'_, Platform>,
        entry: &abi::EntryOut,
        parent: &Arc<Node<Platform, T>>,
    ) -> Result<Arc<Node<Platform, T>>, Error> {
        let mut dirs = self.dirs.lock();
        if let Some(node) = dirs.get(&entry.nodeid).and_then(Weak::upgrade) {
            // A last reference's drop takes the lock.
            drop(dirs);
            node.lookups.fetch_add(1, Ordering::Relaxed);
            Self::reparent(namespace, &node, parent)?;
            return Ok(node);
        }
        let node = Arc::new(Node {
            id: entry.nodeid,
            lookups: AtomicU64::new(1),
            file_type: abi::S_IFDIR,
            parent: Mutex::new(Some(Arc::clone(parent))),
            dirs: Some(Arc::clone(&self.dirs)),
            client: Arc::clone(&self.client),
        });
        dirs.insert(entry.nodeid, Arc::downgrade(&node));
        Ok(node)
    }

    /// Moves the directory `node` to `parent`; fails with `ELOOP` on a loop, as Linux does.
    fn reparent(
        namespace: &Namespace<'_, Platform>,
        node: &Arc<Node<Platform, T>>,
        parent: &Arc<Node<Platform, T>>,
    ) -> Result<(), Error> {
        let current = node.parent.lock().clone();
        if current.is_some_and(|current| Arc::ptr_eq(&current, parent)) {
            return Ok(());
        }
        if Self::is_ancestor(namespace, node, parent) {
            return Err(Error::Remote(ELOOP));
        }
        Self::set_parent(namespace, node, parent);
        Ok(())
    }

    fn set_parent(
        _namespace: &Namespace<'_, Platform>,
        node: &Node<Platform, T>,
        parent: &Arc<Node<Platform, T>>,
    ) {
        let old = node.parent.lock().replace(Arc::clone(parent));
        // After the lock: a last reference's drop forgets.
        drop(old);
    }

    /// Whether `dir` is `descendant` or above it.
    fn is_ancestor(
        _namespace: &Namespace<'_, Platform>,
        dir: &Arc<Node<Platform, T>>,
        descendant: &Arc<Node<Platform, T>>,
    ) -> bool {
        core::iter::successors(Some(Arc::clone(descendant)), |above| {
            above.parent.lock().clone()
        })
        .any(|above| Arc::ptr_eq(&above, dir))
    }

    fn getattr(&self, node: &Node<Platform, T>, fh: Option<u64>) -> Result<abi::Attr, Error> {
        let attr = self.client.getattr(node.id, fh)?;
        node.check_type(&attr)?;
        Ok(attr)
    }

    fn setattr(&self, node: &Node<Platform, T>, attr: client::SetAttr) -> Result<(), Error> {
        let attr = self.client.setattr(node.id, attr)?;
        node.check_type(&attr)
    }

    /// `flags` are the server's `open(2)` flags.
    fn open(
        &self,
        node: &Arc<Node<Platform, T>>,
        flags: u32,
        dir: bool,
    ) -> Result<Arc<Open<Platform, T>>, Error> {
        let open = self.client.open(node.id, flags, dir)?;
        Ok(Arc::new(Open::new(Arc::clone(node), open, flags, dir)))
    }

    /// Of a node's attributes: never a special file's, which `resolve` hides.
    fn file_status(&self, attr: &abi::Attr) -> Result<super::FileStatus, Error> {
        let time = |time: abi::Time| super::FileTimestamp {
            seconds: time.seconds,
            nanoseconds: time.nanoseconds,
        };
        Ok(super::FileStatus {
            file_type: mode_to_file_type(attr.mode).ok_or(Error::InvalidResponse)?,
            mode: super::Mode::from_u32_bits_truncate(attr.mode),
            size: attr.size,
            owner: super::UserInfo {
                user: guest_id(attr.uid),
                group: guest_id(attr.gid),
            },
            node_info: self.node_info(attr.ino),
            blksize: attr.blksize.into(),
            times: Some(super::FileTimestamps {
                accessed: time(attr.atime),
                modified: time(attr.mtime),
                changed: time(attr.ctime),
            }),
        })
    }

    fn node_info(&self, ino: u64) -> super::NodeInfo {
        super::NodeInfo {
            dev: self.device_id,
            ino,
            rdev: None,
        }
    }

    /// A listed name's attributes, by a lookup that also moves a directory found there, loops aside:
    /// as on Linux, only walks fail on them.
    fn lookup_attr(&self, dir: &Arc<Node<Platform, T>>, name: &str) -> Result<abi::Attr, Error> {
        let namespace = self.namespace.lock();
        let entry = self.client.lookup(dir.id, name)?;
        if entry.attr.is_dir() {
            drop(self.dir_node(&namespace, &entry, dir));
        } else {
            self.client.forget(entry.nodeid, 1);
        }
        Ok(entry.attr)
    }

    /// Fails unless the server's user may write and search `dir`: Linux checks it before a removed
    /// name's type.
    fn check_removal(&self, dir: &Node<Platform, T>) -> Result<(), Error> {
        const W_OK: u32 = 2;
        const X_OK: u32 = 1;
        self.client.access(dir.id, W_OK | X_OK)
    }

    /// Looks the new name `name` in `dir` up, as Linux does before creating it: a directory there
    /// moves, and an existing name fails with `EEXIST` without the server.
    fn look_before_creating(
        &self,
        namespace: &Namespace<'_, Platform>,
        dir: &Arc<Node<Platform, T>>,
        name: &str,
    ) -> Result<(), Error> {
        match self.dir_at(namespace, dir, name) {
            Err(Error::Remote(ENOENT)) => Ok(()),
            Ok(_) => Err(Error::Remote(EEXIST)),
            Err(error) => Err(error),
        }
    }
}

/// Forgotten with its last reference.
struct Node<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    id: u64,
    /// The server's count; zero for the root, which is never forgotten.
    lookups: AtomicU64,
    /// `S_IFMT` bits.
    file_type: u32,
    /// A directory's `..` (see the module's docs); none for the root and non-directories. Changes
    /// under the namespace lock.
    parent: Mutex<Platform, Option<Arc<Node<Platform, T>>>>,
    /// A directory's table, which it leaves with its last reference; none for the root.
    dirs: Option<Arc<Dirs<Platform, T>>>,
    client: Arc<client::Client<Platform, T>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Node<Platform, T> {
    /// A file's type never changes, as Linux checks (`inode_wrong_type`).
    fn check_type(&self, attr: &abi::Attr) -> Result<(), Error> {
        if attr.file_type() != self.file_type {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Drop
    for Node<Platform, T>
{
    fn drop(&mut self) {
        if let Some(dirs) = &self.dirs {
            let mut dirs = dirs.lock();
            // Unless a lookup replaced it meanwhile.
            if dirs
                .get(&self.id)
                .is_some_and(|node| node.strong_count() == 0)
            {
                dirs.remove(&self.id);
            }
        }
        let lookups = *self.lookups.get_mut();
        if lookups > 0 {
            self.client.forget(self.id, lookups);
        }
        // The ancestors it alone kept, here rather than by nested drops: a chain can be deeper
        // than the stack.
        let mut parent = self.parent.get_mut().take();
        while let Some(mut node) = parent.and_then(Arc::into_inner) {
            parent = node.parent.get_mut().take();
            drop(node);
        }
    }
}

/// Released with its last reference.
struct Open<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    /// Forgotten only after the release, which names it.
    node: Arc<Node<Platform, T>>,
    fh: u64,
    /// Repeated in the release.
    flags: u32,
    dir: bool,
    fopen_flags: u32,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Open<Platform, T> {
    fn new(node: Arc<Node<Platform, T>>, open: abi::OpenOut, flags: u32, dir: bool) -> Self {
        Self {
            node,
            fh: open.fh,
            flags,
            dir,
            fopen_flags: open.open_flags,
        }
    }

    /// The offset of the request `done` bytes into a transfer at `offset`; always 0 in a stream
    /// (`FOPEN_STREAM`), which has no position.
    fn chunk_offset(&self, offset: usize, done: usize) -> Result<u64, Error> {
        if self.fopen_flags & abi::fopen::STREAM != 0 {
            Ok(0)
        } else {
            offset_after(offset, done)
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Drop
    for Open<Platform, T>
{
    fn drop(&mut self) {
        self.node
            .client
            .release(self.node.id, self.fh, self.flags, self.dir);
    }
}

/// A resolved, unopened directory.
pub struct FuseResolvedDir<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// From its lookup, if it was looked up.
    attr: Option<abi::Attr>,
}

/// A resolved, unopened non-directory.
pub struct FuseResolvedFile<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// From its lookup.
    attr: abi::Attr,
}

/// Directory handle
pub struct FuseDirHandle<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// `None` for an `O_PATH` handle.
    open: Option<Arc<Open<Platform, T>>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Clone
    for FuseDirHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            node: Arc::clone(&self.node),
            open: self.open.clone(),
        }
    }
}

/// File handle
pub struct FuseFileHandle<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> {
    node: Arc<Node<Platform, T>>,
    /// `None` for an `O_PATH` handle.
    open: Option<Arc<Open<Platform, T>>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, T: transport::Transport> Clone
    for FuseFileHandle<Platform, T>
{
    fn clone(&self) -> Self {
        Self {
            node: Arc::clone(&self.node),
            open: self.open.clone(),
        }
    }
}

impl<Platform, T> super::backend::BackendHandles for Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + 'static,
{
    type ResolvedDir<'a> = FuseResolvedDir<Platform, T>;
    type ResolvedFile<'a> = FuseResolvedFile<Platform, T>;
    type FileHandle = FuseFileHandle<Platform, T>;
    type DirHandle = FuseDirHandle<Platform, T>;
}

impl<Platform, T> Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + 'static,
{
    fn handle_parts(h: HandleRef<'_>) -> (&Arc<Node<Platform, T>>, Option<u64>) {
        let (node, open) = match h {
            HandleRef::File(h) => {
                let h = h.get_typed::<Self>();
                (&h.node, &h.open)
            }
            HandleRef::Dir(h) => {
                let h = h.get_typed::<Self>();
                (&h.node, &h.open)
            }
        };
        (node, open.as_ref().map(|open| open.fh))
    }

    fn target_node(target: ResolvedTarget<'_>) -> Arc<Node<Platform, T>> {
        match target {
            ResolvedTarget::File(file) => file.into_typed::<Self>().node,
            ResolvedTarget::Dir(dir) => dir.into_typed::<Self>().node,
        }
    }

    fn resolved_dir<'a>(dir: FuseResolvedDir<Platform, T>) -> ResolvedDir<'a> {
        ResolvedDir::from_typed::<Self>(dir, PermissionCheck::ByBackend)
    }
}

impl<Platform, T> super::backend::Backend for Fuse<Platform, T>
where
    Platform: sync::RawSyncPrimitivesProvider + 'static,
    T: transport::Transport + 'static,
{
    fn root(&self, _caller: Caller<'_>) -> Result<ResolvedDir<'_>, WalkError> {
        Ok(Self::resolved_dir(FuseResolvedDir {
            node: Arc::clone(&self.root),
            attr: None,
        }))
    }

    fn resolve<'a>(
        &'a self,
        _caller: Caller<'_>,
        from: ResolvedDir<'a>,
        components: &[&str],
        _authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        let mut current = from.into_typed::<Self>();
        for (index, name) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            let found = {
                let namespace = self.namespace.lock();
                self.lookup(&namespace, &current.node, name)
            };
            let entry = match found {
                Ok(Found::Dir(node, attr)) => {
                    current = FuseResolvedDir {
                        node,
                        attr: Some(attr),
                    };
                    continue;
                }
                Ok(Found::Other(entry)) => entry,
                Err(Error::Remote(ENOENT)) if last => {
                    return Ok(Resolution::MissingFinal {
                        parent: Self::resolved_dir(current),
                    });
                }
                Err(error) => {
                    return Err(ResolutionError {
                        component: Some(index),
                        error: error.into(),
                    });
                }
            };
            let node = self.own_file(&entry);
            let Some(file_type) = mode_to_file_type(entry.attr.mode) else {
                // Hidden, as in listings; `EINVAL`, as for the userland broker's host files.
                return Err(ResolutionError {
                    component: Some(index),
                    error: PathError::InvalidPathname.into(),
                });
            };
            if !last {
                return Err(ResolutionError {
                    component: Some(index + 1),
                    error: PathError::ComponentNotADirectory.into(),
                });
            }
            return Ok(Resolution::Found(ResolvedTarget::File(
                ResolvedFile::from_typed::<Self>(
                    FuseResolvedFile {
                        node,
                        attr: entry.attr,
                    },
                    PermissionCheck::ByBackend,
                    file_type,
                ),
            )));
        }
        Ok(Resolution::Found(ResolvedTarget::Dir(Self::resolved_dir(
            current,
        ))))
    }

    fn read_link_at(
        &self,
        _caller: Caller<'_>,
        dir: &ResolvedDir<'_>,
        name: &str,
    ) -> Result<String, WalkError> {
        let found = {
            let namespace = self.namespace.lock();
            self.lookup(&namespace, &dir.get_typed::<Self>().node, name)?
        };
        let Found::Other(entry) = found else {
            return Err(PathError::InvalidPathname.into());
        };
        let node = self.own_file(&entry);
        if entry.attr.file_type() != abi::S_IFLNK {
            return Err(PathError::InvalidPathname.into());
        }
        let target = self.client.readlink(node.id)?;
        // Unchanged: an absolute target resolves from the guest's root, not the export's.
        String::from_utf8(target).map_err(|_| PathError::InvalidPathname.into())
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        assert_supported_oflags(flags);
        let node = dir.into_typed::<Self>().node;
        let open = if flags.contains(OFlags::PATH) {
            None
        } else {
            // As for 9P, directories are opened for reading only, whatever was asked for.
            Some(self.open(&node, OFlags::DIRECTORY.bits(), true)?)
        };
        Ok(DirHandle::from_typed::<Self>(FuseDirHandle { node, open }))
    }

    /// Node ids name directories, not paths: a renamed one is still walked.
    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Result<ResolvedDir<'a>, WalkError> {
        Ok(Self::resolved_dir(FuseResolvedDir {
            node: Arc::clone(&dir.get_typed::<Self>().node),
            attr: None,
        }))
    }

    /// FUSE cannot ask for a node's name, so only the root's is known, as for 9P.
    fn dir_path(
        &self,
        _caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<Vec<String>>, WalkError> {
        let node = &dir.get_typed::<Self>().node;
        if node.id == abi::ROOT_ID {
            return Ok(Some(Vec::new()));
        }
        if self.getattr(node, None)?.nlink == 0 {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        Ok(None)
    }

    fn parent_dir(
        &self,
        _caller: Caller<'_>,
        dir: &DirHandle,
    ) -> Result<Option<DirHandle>, WalkError> {
        let parent = {
            let _namespace = self.namespace.lock();
            dir.get_typed::<Self>().node.parent.lock().clone()
        };
        Ok(parent.map(|node| DirHandle::from_typed::<Self>(FuseDirHandle { node, open: None })))
    }

    fn check_search_permission(&self, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        const X_OK: u32 = 1;
        Ok(self.client.access(dir.get_typed::<Self>().node.id, X_OK)?)
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        assert_supported_oflags(flags);
        // As for 9P, `O_NONBLOCK` is ignored.
        let flags = flags - OFlags::NONBLOCK;
        if flags.contains(OFlags::DIRECTORY) {
            return Err(OpenError::PathError(PathError::ComponentNotADirectory));
        }
        let FuseResolvedFile { node, .. } = file.into_typed::<Self>();
        if flags.contains(OFlags::PATH) {
            return Ok(FileHandle::from_typed::<Self>(FuseFileHandle {
                node,
                open: None,
            }));
        }
        let truncate = flags.contains(OFlags::TRUNC);
        let atomic_o_trunc = self.client.atomic_o_trunc();
        let mut open_flags = flags;
        if !atomic_o_trunc {
            open_flags -= OFlags::TRUNC;
        }
        let open = self.open(&node, oflags_to_open(open_flags), false)?;
        if truncate && !atomic_o_trunc {
            // By node, not through the handle, which may be read-only (`O_RDONLY | O_TRUNC`).
            self.setattr(
                &node,
                client::SetAttr {
                    valid: abi::fattr::SIZE,
                    ..Default::default()
                },
            )?;
        }
        Ok(FileHandle::from_typed::<Self>(FuseFileHandle {
            node,
            open: Some(open),
        }))
    }

    fn list_dir_at(
        &self,
        _caller: Caller<'_>,
        handle: DirHandle,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let handle = handle.into_typed::<Self>();
        let open = match handle.open {
            Some(open) => open,
            None => self.open(&handle.node, OFlags::DIRECTORY.bits(), true)?,
        };
        let entries = self.client.readdir_all(open.node.id, open.fh)?;
        let mut listed = Vec::new();
        listed
            .try_reserve_exact(entries.len())
            .map_err(out_of_memory)?;
        for entry in entries {
            // The resolver synthesizes `.` and `..` itself.
            if matches!(&*entry.name, b"." | b"..") {
                continue;
            }
            // As for the userland broker's host files: a lossy conversion could name another entry.
            let Ok(name) = String::from_utf8(entry.name) else {
                continue;
            };
            let (file_type, ino) = if entry.typ == DT_UNKNOWN {
                // An entry removed since, or that the server's user may not look up, is not
                // listed; other failures would leave the listing incomplete.
                match self.lookup_attr(&open.node, &name) {
                    Ok(attr) => (mode_to_file_type(attr.mode), attr.ino),
                    Err(Error::Remote(ENOENT | EACCES | EPERM)) => continue,
                    Err(error) => return Err(error.into()),
                }
            } else {
                (dt_to_file_type(entry.typ), entry.ino)
            };
            // A special file, hidden (see the module's docs).
            let Some(file_type) = file_type else {
                continue;
            };
            listed.push(super::DirEntry {
                name,
                file_type,
                ino_info: Some(self.node_info(ino)),
            });
        }
        Ok(listed)
    }

    /// As many `FUSE_READ`s as it takes to fill `buf`, short of the end of the file: each
    /// request to the broker costs more than a request to the server.
    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let h = h.get_typed::<Self>();
        let open = h.open.as_ref().ok_or(ReadError::NotForReading)?;
        let max = self.client.max_read();
        let len = within_max_offset(offset, buf.len());
        let read = transfer(len, max, |done, count| {
            let offset = open.chunk_offset(offset, done)?;
            self.client
                .read(h.node.id, open.fh, offset, buf, done, count)
        })?;
        Ok(read)
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let h = h.get_typed::<Self>();
        let open = h.open.as_ref().ok_or(WriteError::NotForWriting)?;
        let max = self.client.max_write();
        let len = within_max_offset(offset, buf.len());
        if len == 0 && !buf.is_empty() {
            // Linux's `EFBIG`.
            return Err(WriteError::NoSpace);
        }
        let written = transfer(len, max, |done, count| {
            let offset = open.chunk_offset(offset, done)?;
            self.client
                .write(h.node.id, open.fh, offset, buf, done, count)
        })?;
        Ok(written)
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let (node, fh) = Self::handle_parts(HandleRef::File(h));
        // Linux's `EFBIG`.
        let size = u64::try_from(length)
            .ok()
            .filter(|&size| size <= i64::MAX.cast_unsigned())
            .ok_or(TruncateError::NoSpace)?;
        let mut attr = client::SetAttr {
            valid: abi::fattr::SIZE,
            size,
            ..Default::default()
        };
        if let Some(fh) = fh {
            attr.valid |= abi::fattr::FH;
            attr.fh = fh;
        }
        self.setattr(node, attr)?;
        Ok(())
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        let h = h.get_typed::<Self>();
        let fopen_flags = h.open.as_ref().map_or(0, |open| open.fopen_flags);
        if fopen_flags & abi::fopen::STREAM != 0 {
            SeekBehavior::NonSeekable
        } else if fopen_flags & abi::fopen::NONSEEKABLE != 0 {
            // Unlike Linux, `pread` and `pwrite` still work: the resolver cannot tell them from
            // the offset reads that loading executables and mappings need.
            SeekBehavior::PositionBasedNonSeekable
        } else {
            SeekBehavior::PositionBased
        }
    }

    fn status(
        &self,
        _caller: Caller<'_>,
        h: HandleRef<'_>,
    ) -> Result<super::FileStatus, FileStatusError> {
        let (node, fh) = Self::handle_parts(h);
        // Only a file's handle goes with `FUSE_GETATTR_FH`, as on Linux: directory handles are
        // another namespace on some servers.
        let fh = match h {
            HandleRef::File(_) => fh,
            HandleRef::Dir(_) => None,
        };
        let attr = self.getattr(node, fh)?;
        Ok(self.file_status(&attr)?)
    }

    /// Reuses the lookup's attributes when present.
    fn resolved_status(
        &self,
        _caller: Caller<'_>,
        target: &ResolvedTarget<'_>,
    ) -> Result<super::FileStatus, FileStatusError> {
        let (node, attr) = match target {
            ResolvedTarget::File(file) => {
                let file = file.get_typed::<Self>();
                (&file.node, Some(file.attr))
            }
            ResolvedTarget::Dir(dir) => {
                let dir = dir.get_typed::<Self>();
                (&dir.node, dir.attr)
            }
        };
        let attr = match attr {
            Some(attr) => attr,
            None => self.getattr(node, None)?,
        };
        Ok(self.file_status(&attr)?)
    }

    fn create_file_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        let dir = dir.into_typed::<Self>();
        // As with 9P, the server needs an access mode; the resolver enforces the caller's.
        let flags = (OFlags::RDWR | OFlags::CREAT | OFlags::EXCL).bits();
        let (entry, open) = {
            let _namespace = self.namespace.lock();
            let mode = abi::S_IFREG | host_mode(metadata.mode);
            self.client.create(dir.node.id, name, flags, mode)?
        };
        let node = self.own_file(&entry);
        let open = Arc::new(Open::new(Arc::clone(&node), open, flags, false));
        Ok(FileHandle::from_typed::<Self>(FuseFileHandle {
            node,
            open: Some(open),
        }))
    }

    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        _metadata: super::backend::CreationMetadata,
    ) -> Result<(), SymlinkError> {
        let dir = dir.into_typed::<Self>();
        let entry = {
            let namespace = self.namespace.lock();
            self.look_before_creating(&namespace, &dir.node, name)?;
            self.client.symlink(dir.node.id, name, target)?
        };
        // The creation counted a lookup.
        self.client.forget(entry.nodeid, 1);
        Ok(())
    }

    fn mkdir_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        metadata: super::backend::CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        let dir = dir.into_typed::<Self>();
        let namespace = self.namespace.lock();
        self.look_before_creating(&namespace, &dir.node, name)?;
        let entry = (self.client).mkdir(dir.node.id, name, host_mode(metadata.mode))?;
        Ok(DirHandle::from_typed::<Self>(FuseDirHandle {
            node: self.dir_node(&namespace, &entry, &dir.node)?,
            open: None,
        }))
    }

    fn unlink_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        let dir = dir.into_typed::<Self>();
        let namespace = self.namespace.lock();
        // As Linux, by the name's lookup, which moves a directory there.
        if self.dir_at(&namespace, &dir.node, name)?.is_some() {
            self.check_removal(&dir.node)?;
            return Err(UnlinkError::IsADirectory);
        }
        Ok(self.client.remove(dir.node.id, name, false)?)
    }

    fn rmdir_at(&self, dir: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        let dir = dir.into_typed::<Self>();
        let namespace = self.namespace.lock();
        // As Linux, by the name's lookup: a removed directory keeps its parent at its removal.
        let Some(_removed) = self.dir_at(&namespace, &dir.node, name)? else {
            self.check_removal(&dir.node)?;
            return Err(RmdirError::NotADirectory);
        };
        Ok(self.client.remove(dir.node.id, name, true)?)
    }

    /// The server's `renameat` neither follows a final symlink nor moves a directory into itself.
    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        let old_dir = old_dir.into_typed::<Self>();
        let new_dir = new_dir.into_typed::<Self>();
        let namespace = self.namespace.lock();
        // As Linux moves the source's dentry, the directory found at the old name moves, whatever the
        // host does meanwhile; the new name's lookup, at the end, finds what the server moved.
        let moved = self.dir_at(&namespace, &old_dir.node, old_name)?;
        // A replaced directory keeps its parent at its removal.
        let replaced = match self.dir_at(&namespace, &new_dir.node, new_name) {
            Err(Error::Remote(ENOENT)) => None,
            found => found?,
        };
        // As Linux checks its dentries.
        if let Some(moved) = &moved
            && Self::is_ancestor(&namespace, moved, &new_dir.node)
        {
            return Err(RenameError::InvalidArgument);
        }
        if let Some(replaced) = &replaced
            && Self::is_ancestor(&namespace, replaced, &old_dir.node)
        {
            return Err(RenameError::NotEmpty);
        }
        (self.client).rename(old_dir.node.id, old_name, new_dir.node.id, new_name)?;
        if let Some(moved) = &moved {
            // No loop: checked above, under the lock.
            Self::set_parent(&namespace, moved, &new_dir.node);
        }
        // Best effort: the rename is done.
        drop(self.dir_at(&namespace, &new_dir.node, new_name));
        Ok(())
    }

    fn set_times(
        &self,
        target: ResolvedTarget<'_>,
        times: &super::SetFileTimes,
    ) -> Result<(), SetTimesError> {
        use super::FileTimeUpdate;
        let node = Self::target_node(target);
        let mut attr = client::SetAttr::default();
        for (update, value, set, now) in [
            (
                times.access,
                &mut attr.atime,
                abi::fattr::ATIME,
                abi::fattr::ATIME_NOW,
            ),
            (
                times.modify,
                &mut attr.mtime,
                abi::fattr::MTIME,
                abi::fattr::MTIME_NOW,
            ),
        ] {
            match update {
                FileTimeUpdate::Omit => {}
                // The server's clock, as for its files' other timestamps.
                FileTimeUpdate::Now => attr.valid |= set | now,
                FileTimeUpdate::Set(time) => {
                    attr.valid |= set;
                    *value = abi::Time {
                        seconds: time.seconds,
                        nanoseconds: time.nanoseconds,
                    };
                }
            }
        }
        if attr.valid == 0 {
            return Ok(());
        }
        self.setattr(&node, attr)?;
        Ok(())
    }

    fn chmod(&self, target: ResolvedTarget<'_>, mode: super::Mode) -> Result<(), ChmodError> {
        let node = Self::target_node(target);
        self.setattr(
            &node,
            client::SetAttr {
                valid: abi::fattr::MODE,
                mode: host_mode(mode),
                ..Default::default()
            },
        )?;
        Ok(())
    }

    fn chown(
        &self,
        target: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let node = Self::target_node(target);
        let mut attr = client::SetAttr::default();
        if let Some(user) = user {
            attr.valid |= abi::fattr::UID;
            attr.uid = user.into();
        }
        if let Some(group) = group {
            attr.valid |= abi::fattr::GID;
            attr.gid = group.into();
        }
        if attr.valid == 0 {
            return Ok(());
        }
        self.setattr(&node, attr)?;
        Ok(())
    }
}

/// Transfers `len` bytes in `step(done, count)`s of at most `max` bytes, until one transfers less.
///
/// Bytes already transferred are reported rather than a later step's error, as `read(2)` and
/// `write(2)` do, unless the broker itself failed (e.g., a copy faulted).
fn transfer(
    len: usize,
    max: usize,
    mut step: impl FnMut(usize, usize) -> Result<usize, Error>,
) -> Result<usize, Error> {
    let mut done = 0;
    while done < len {
        let asked = (len - done).min(max);
        match step(done, asked) {
            Ok(n) => {
                done += n;
                if n < asked {
                    break;
                }
            }
            Err(error @ Error::Broker(_)) => return Err(error),
            Err(_) if done > 0 => break,
            Err(error) => return Err(error),
        }
    }
    Ok(done)
}

/// How many of `len` bytes from `offset` lie before `i64::MAX`, the largest `off_t` (which also
/// bounds the sizes the server reports): positions after a transfer cannot overflow.
fn within_max_offset(offset: usize, len: usize) -> usize {
    let room = u64::try_from(offset)
        .ok()
        .and_then(|offset| i64::MAX.cast_unsigned().checked_sub(offset))
        .unwrap_or(0);
    usize::try_from(room).map_or(len, |room| len.min(room))
}

fn out_of_memory(_: alloc::collections::TryReserveError) -> Error {
    BrokerError::OutOfMemory.into()
}

fn offset_after(offset: usize, done: usize) -> Result<u64, Error> {
    offset
        .checked_add(done)
        .and_then(|offset| u64::try_from(offset).ok())
        .ok_or(Error::Remote(EINVAL))
}

/// Ids beyond `u16` are the overflow id, as for the userland broker's host files.
fn guest_id(id: u32) -> u16 {
    u16::try_from(id).unwrap_or(super::tar_ro::OVERFLOW_ID)
}

/// As the userland broker's `host_mode`: no setuid or setgid bits.
fn host_mode(mode: super::Mode) -> u32 {
    u32::from((mode - super::Mode::SUID - super::Mode::SGID).bits())
}

/// Flags this backend knows how to honor when opening files/directories.
const SUPPORTED_OFLAGS: OFlags = OFlags::CREAT
    .union(OFlags::RDONLY)
    .union(OFlags::WRONLY)
    .union(OFlags::RDWR)
    .union(OFlags::TRUNC)
    .union(OFlags::NOCTTY)
    .union(OFlags::EXCL)
    .union(OFlags::DIRECTORY)
    .union(OFlags::NONBLOCK)
    .union(OFlags::LARGEFILE)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::APPEND)
    .union(OFlags::PATH);

fn assert_supported_oflags(flags: OFlags) {
    if flags.intersects(SUPPORTED_OFLAGS.complement()) {
        unimplemented!("{flags:?}")
    }
}

/// The guest's flags, untranslated, as from Linux's client: FUSE fixes no encoding, so the server
/// must share the guest's architecture, as a virtio-fs device under KVM does.
fn oflags_to_open(flags: OFlags) -> u32 {
    // Not `O_CREAT`, `O_EXCL`, or `O_NOCTTY`, as from Linux's client; nor `O_APPEND`: the resolver
    // writes appends at the end itself, and `F_SETFL` can change it after the open. `O_NOFOLLOW`
    // and `O_DIRECTORY` concern the lookup, which is done.
    const PASSED: OFlags = OFlags::RDONLY
        .union(OFlags::WRONLY)
        .union(OFlags::RDWR)
        .union(OFlags::TRUNC)
        .union(OFlags::LARGEFILE);
    (flags & PASSED).bits()
}

/// `None` for a special file.
fn mode_to_file_type(mode: u32) -> Option<super::FileType> {
    match mode & abi::S_IFMT {
        abi::S_IFREG => Some(super::FileType::RegularFile),
        abi::S_IFDIR => Some(super::FileType::Directory),
        abi::S_IFLNK => Some(super::FileType::SymbolicLink),
        _ => None,
    }
}

/// As [`mode_to_file_type`], of a listed entry's type, other than `DT_UNKNOWN`.
fn dt_to_file_type(typ: u32) -> Option<super::FileType> {
    match typ {
        abi::DT_REG => Some(super::FileType::RegularFile),
        abi::DT_DIR => Some(super::FileType::Directory),
        abi::DT_LNK => Some(super::FileType::SymbolicLink),
        _ => None,
    }
}

const DT_UNKNOWN: u32 = 0;

const EPERM: u32 = 1;
const ENOENT: u32 = 2;
const ENXIO: u32 = 6;
const EACCES: u32 = 13;
const EBUSY: u32 = 16;
const EEXIST: u32 = 17;
const EXDEV: u32 = 18;
const ENODEV: u32 = 19;
const ENOTDIR: u32 = 20;
const EISDIR: u32 = 21;
const EINVAL: u32 = 22;
const EFBIG: u32 = 27;
const ENOSPC: u32 = 28;
const EROFS: u32 = 30;
const ENAMETOOLONG: u32 = 36;
const ENOSYS: u32 = 38;
const ENOTEMPTY: u32 = 39;
const ELOOP: u32 = 40;
const EOPNOTSUPP: u32 = 95;
const EDQUOT: u32 = 122;

/// Error type for FUSE operations
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io,

    #[error("Invalid response from server")]
    InvalidResponse,

    #[error("Invalid pathname")]
    InvalidPathname,

    /// An errno from the server.
    #[error("Remote error (errno={0})")]
    Remote(u32),

    /// The broker itself failed, e.g., a copy to or from the caller's buffer faulted.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl From<Fault> for Error {
    fn from(fault: Fault) -> Self {
        Self::Broker(fault.into())
    }
}

fn path_error(errno: u32) -> Option<PathError> {
    Some(match errno {
        ENOENT => PathError::NoSuchFileOrDirectory,
        ENOTDIR => PathError::ComponentNotADirectory,
        ENAMETOOLONG => PathError::InvalidPathname,
        ELOOP => PathError::TooManySymlinks,
        _ => return None,
    })
}

impl From<Error> for OpenError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EEXIST => Self::AlreadyExists,
                EPERM | EACCES => Self::AccessNotAllowed,
                EROFS => Self::ReadOnlyFileSystem,
                ENXIO | ENODEV => Self::NoSuchDevice,
                ENOSPC | EDQUOT => Self::NoSpace,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for ReadError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                EISDIR => Self::NotAFile,
                EPERM | EACCES => Self::NotForReading,
                _ => Self::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => Self::Io,
            Error::Broker(error) => Self::Broker(error),
        }
    }
}

impl From<Error> for WriteError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                EISDIR => Self::NotAFile,
                EPERM | EACCES => Self::NotForWriting,
                ENOSPC | EDQUOT | EFBIG => Self::NoSpace,
                _ => Self::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname => Self::Io,
            Error::Broker(error) => Self::Broker(error),
        }
    }
}

impl From<Error> for MkdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EEXIST => Self::AlreadyExists,
                EPERM | EACCES => Self::NoWritePerms,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for SymlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EEXIST => Self::AlreadyExists,
                EPERM | EACCES => Self::NoWritePerms,
                EROFS => Self::ReadOnlyFileSystem,
                ENOSYS | EOPNOTSUPP => Self::NotSupported,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for ReadDirError {
    fn from(e: Error) -> Self {
        match e {
            // Reading an open directory fails with `ENOENT` once it has been removed.
            Error::Remote(ENOENT) => Self::Removed,
            Error::Remote(ENOTDIR) => Self::NotADirectory,
            Error::Remote(_)
            | Error::Io
            | Error::InvalidResponse
            | Error::InvalidPathname
            | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for UnlinkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EISDIR => Self::IsADirectory,
                EPERM | EACCES => Self::NoWritePerms,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for RmdirError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                ENOTDIR => Self::NotADirectory,
                EPERM | EACCES => Self::NoWritePerms,
                ENOTEMPTY | EEXIST => Self::NotEmpty,
                EBUSY => Self::Busy,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for RenameError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EPERM | EACCES => Self::NoWritePerms,
                EBUSY => Self::Busy,
                // Unsupported atomic rename is EXDEV, never copy/delete.
                EXDEV | ENOSYS | EOPNOTSUPP => Self::CrossDevice,
                EINVAL => Self::InvalidArgument,
                EISDIR => Self::IsADirectory,
                ENOTDIR => Self::NotADirectory,
                ENOTEMPTY | EEXIST => Self::NotEmpty,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for FileStatusError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(EPERM | EACCES) => Self::PathError(PathError::NoSearchPerms),
            Error::Remote(errno) => path_error(errno).map_or(Self::Io, Self::PathError),
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for TruncateError {
    fn from(e: Error) -> Self {
        match e {
            Error::Remote(errno) => match errno {
                ENOENT => Self::ClosedFd,
                EISDIR => Self::IsDirectory,
                EPERM | EACCES => Self::NotForWriting,
                ENOSPC | EDQUOT | EFBIG => Self::NoSpace,
                _ => Self::Io,
            },
            Error::Io | Error::InvalidResponse | Error::InvalidPathname | Error::Broker(_) => {
                Self::Io
            }
        }
    }
}

impl From<Error> for SetTimesError {
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EPERM => Self::NotTheOwner,
                EACCES => Self::AccessNotAllowed,
                EROFS => Self::ReadOnlyFileSystem,
                ENOSYS | EOPNOTSUPP => Self::NotSupported,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for ChmodError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EPERM | EACCES => Self::NotTheOwner,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for ChownError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(errno) => match errno {
                EPERM | EACCES => Self::NotTheOwner,
                EROFS => Self::ReadOnlyFileSystem,
                _ => path_error(errno).map_or(Self::Io, Self::PathError),
            },
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}

impl From<Error> for WalkError {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidPathname => Self::PathError(PathError::InvalidPathname),
            Error::Remote(EPERM | EACCES) => Self::PathError(PathError::NoSearchPerms),
            Error::Remote(errno) => path_error(errno).map_or(Self::Io, Self::PathError),
            Error::Io | Error::InvalidResponse | Error::Broker(_) => Self::Io,
        }
    }
}
