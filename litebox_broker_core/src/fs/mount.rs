// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mount trees: the mounts of a mount namespace, and the locations in them that path resolution
//! walks.
//!
//! A mount shows a backend, or one of its directories or files (a bind), at a point of its parent
//! mount. A namespace's mounts form a tree, which is copied on write: readers take a snapshot (an
//! `Arc` clone) and walk it without holding a lock, so no lock here is ever held across a backend
//! call. Mount types, sources and options are opaque strings to the core.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::mount::MountInfo;
use spin::{Mutex, RwLock};

use super::backend::{Backend, DirHandle, PermissionInfo, Resolution, ResolvedTarget};
use super::errors::{FileStatusError, PathError, WalkError};
use super::inode_allocator::InodeAllocators;
use super::service::FileOps;
use super::{FileResult, FileType};
use crate::BrokerProcess;
use crate::quota::QuotaReservation;

/// Identifies a mount. Never reused among the mounts of a namespace and the namespaces copied from
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MountId(u64);

impl MountId {
    /// The identifier as a number, as Linux's `mountinfo` shows one.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Identifies a mount namespace, like [`MountId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MountNamespaceId(u64);

/// What a namespace shares with the namespaces copied from it: the identifiers of their mounts,
/// and the registry of the points their mounts are attached at.
pub(crate) struct MountFamily {
    next_id: AtomicU64,
    /// Shared by every namespace whose backends take their devices from the same
    /// [`InodeAllocators`], which keeps it.
    points: Arc<MountPoints>,
}

/// The points of backends that mounts are attached at: by backend (the address of its data), the
/// paths inside it that mounts are attached at, and those that removals and renames are changing,
/// so neither starts on what the other uses, as Linux's mount points can be neither removed nor
/// renamed.
///
/// A backend is covered whichever mount, bind or namespace reaches it, as long as they all share
/// this registry: [`InodeAllocators`] keeps one, so file services that can mount the same backend
/// must share their allocators, as they must anyway to keep node identities distinct.
pub(crate) struct MountPoints {
    /// No other lock is taken while this one is held.
    points: Mutex<HashMap<usize, BackendPoints>>,
}

impl core::fmt::Debug for MountPoints {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MountPoints").finish_non_exhaustive()
    }
}

#[derive(Default)]
struct BackendPoints {
    /// How many mounts are attached at each path.
    pinned: HashMap<Vec<String>, usize>,
    /// How many removals or renames are changing each path.
    reserved: HashMap<Vec<String>, usize>,
}

impl BackendPoints {
    fn is_empty(&self) -> bool {
        self.pinned.is_empty() && self.reserved.is_empty()
    }
}

fn backend_key(backend: &Arc<dyn Backend>) -> usize {
    Arc::as_ptr(backend).cast::<()>().addr()
}

/// Take one from the count of `path` in `counts`, forgetting it at zero.
fn uncount(counts: &mut HashMap<Vec<String>, usize>, path: &[String]) {
    if let Some(count) = counts.get_mut(path) {
        *count -= 1;
        if *count == 0 {
            counts.remove(path);
        }
    }
}

impl MountFamily {
    fn new(points: Arc<MountPoints>) -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(1),
            points,
        })
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl MountPoints {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            points: Mutex::new(HashMap::new()),
        })
    }

    /// Pin `path` inside `backend`, where a mount is to be attached, until the pin drops. Fails
    /// with [`FileError::Busy`] while a removal or rename is changing it or a directory above it.
    fn pin(self: &Arc<Self>, backend: &Arc<dyn Backend>, path: Vec<String>) -> FileResult<Pin> {
        let mut points = self.points.lock();
        let entry = points.entry(backend_key(backend)).or_default();
        if entry
            .reserved
            .keys()
            .any(|reserved| path.starts_with(reserved))
        {
            return Err(FileError::Busy);
        }
        *entry.pinned.entry(path.clone()).or_default() += 1;
        drop(points);
        Ok(Pin {
            points: Arc::clone(self),
            backend: Arc::clone(backend),
            path,
        })
    }

    /// Pin `path` inside `backend` again, for a copy of a mount attached there. Only while a pin of
    /// the same path is held, which no removal or rename of it can have started under; one of a
    /// directory above it, which would fail as not empty, doesn't stop this.
    fn pin_again(self: &Arc<Self>, backend: &Arc<dyn Backend>, path: Vec<String>) -> Pin {
        let mut points = self.points.lock();
        let entry = points.entry(backend_key(backend)).or_default();
        *entry.pinned.entry(path.clone()).or_default() += 1;
        drop(points);
        Pin {
            points: Arc::clone(self),
            backend: Arc::clone(backend),
            path,
        }
    }

    /// Reserve `paths` inside `backend` for a removal or rename, until the reservation drops.
    /// Fails with [`FileError::Busy`] while a mount is attached at one of them, or, for those
    /// marked, below one.
    fn reserve(
        self: &Arc<Self>,
        backend: &Arc<dyn Backend>,
        paths: Vec<(Vec<String>, bool)>,
    ) -> FileResult<Reservation> {
        let mut points = self.points.lock();
        let entry = points.entry(backend_key(backend)).or_default();
        let busy = paths.iter().any(|(path, below)| {
            entry
                .pinned
                .keys()
                .any(|pinned| pinned == path || (*below && pinned.starts_with(path)))
        });
        if busy {
            if entry.is_empty() {
                points.remove(&backend_key(backend));
            }
            return Err(FileError::Busy);
        }
        for (path, _) in &paths {
            *entry.reserved.entry(path.clone()).or_default() += 1;
        }
        drop(points);
        Ok(Reservation {
            points: Arc::clone(self),
            backend: Arc::clone(backend),
            paths: paths.into_iter().map(|(path, _)| path).collect(),
        })
    }

    /// Forget one pin or reservation of `path` inside the backend `key`.
    fn release(&self, key: usize, path: &[String], pinned: bool) {
        let mut points = self.points.lock();
        if let Some(entry) = points.get_mut(&key) {
            uncount(
                if pinned {
                    &mut entry.pinned
                } else {
                    &mut entry.reserved
                },
                path,
            );
            if entry.is_empty() {
                points.remove(&key);
            }
        }
    }
}

/// A path inside a backend that a mount is attached at, which removals and renames can't change
/// until this drops.
pub(crate) struct Pin {
    points: Arc<MountPoints>,
    /// Kept alive, so its address can't name another backend while pinned.
    backend: Arc<dyn Backend>,
    path: Vec<String>,
}

impl Drop for Pin {
    fn drop(&mut self) {
        self.points
            .release(backend_key(&self.backend), &self.path, true);
    }
}

/// Paths inside a backend that a removal or rename is changing, where no mount can be attached
/// until this drops.
pub(crate) struct Reservation {
    points: Arc<MountPoints>,
    /// Kept alive, so its address can't name another backend while reserved.
    backend: Arc<dyn Backend>,
    paths: Vec<Vec<String>>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let key = backend_key(&self.backend);
        for path in &self.paths {
            self.points.release(key, path, false);
        }
    }
}

/// What a mount shows at its root.
#[derive(Clone)]
pub(crate) enum MountRoot {
    /// The whole backend, walked from [`Backend::root`].
    Backend,
    /// A directory of the backend (a bind), through an owned handle opened when the mount was made.
    Dir(DirHandle),
    /// A non-directory, non-symlink node of the backend (a file bind), found by looking `name` up in
    /// `parent`. The node there must still be the one bound, `node` (its device and inode numbers),
    /// as the mount can't hold the node itself.
    File {
        parent: DirHandle,
        name: String,
        node: (u64, u64),
    },
}

impl MountRoot {
    /// The root of a bind of the node `name` in `parent`, a directory of `backend`. Fails with
    /// [`PathError::NoSuchFileOrDirectory`] if the node is missing, a directory or a symbolic link.
    pub(crate) fn file(
        backend: &dyn Backend,
        parent: DirHandle,
        name: String,
    ) -> Result<Self, WalkError> {
        let dir = backend.walking_dir_at(&parent).ok_or(WalkError::Io)?;
        let target = found(
            backend
                .resolve(dir, &[name.as_str()], &allow_lookup)
                .map_err(|error| error.error)?,
        )?;
        let node = bound_file_node(backend, &target)?;
        Ok(Self::File { parent, name, node })
    }
}

/// The device and inode numbers of `target`, if a mount of a file can show it: if it is neither a
/// directory nor a symbolic link.
fn bound_file_node(
    backend: &dyn Backend,
    target: &ResolvedTarget<'_>,
) -> Result<(u64, u64), WalkError> {
    match target {
        ResolvedTarget::File(file) if file.file_type != FileType::SymbolicLink => {}
        _ => return Err(PathError::NoSuchFileOrDirectory.into()),
    }
    let status = backend
        .resolved_status(target)
        .map_err(|error| match error {
            FileStatusError::PathError(error) => WalkError::PathError(error),
            FileStatusError::ClosedFd | FileStatusError::Io => WalkError::Io,
        })?;
    Ok((status.node_info.dev, status.node_info.ino))
}

/// The target of `resolution`, failing with [`PathError::NoSuchFileOrDirectory`] if it is missing.
fn found(resolution: Resolution<'_>) -> Result<ResolvedTarget<'_>, WalkError> {
    match resolution {
        Resolution::Found(target) => Ok(target),
        Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
    }
}

/// The bit of [`Mount::writes`] that makes a mount read-only.
const READ_ONLY: usize = 1 << (usize::BITS - 1);

/// A backend, or a node of one, shown in a mount tree.
pub(crate) struct Mount {
    id: MountId,
    family: Arc<MountFamily>,
    /// Shared by binds of the backend and by copies of the mount.
    backend: Arc<dyn Backend>,
    root: MountRoot,
    /// The root's path inside the backend, used when the root's handle is stale.
    backend_root: Vec<String>,
    info: MountInfo,
    /// Open files, and roots and working directories, on this mount, which keep it busy: the
    /// [`HeldLocation`]s on it.
    users: AtomicUsize,
    /// Whether writes through this mount fail ([`READ_ONLY`]), and how many are in progress
    /// through it, counting files open for writing on it, which keep it from becoming read-only:
    /// the [`MountWriter`]s on it. In one word, so a write can start only while the mount is
    /// writable, and the mount can become read-only only while no write is in progress.
    writes: AtomicUsize,
    /// The namespace whose tree this mount is attached to; dangling when it is detached. Written
    /// under that namespace's `mutation` lock; its own lock is held only to clone the `Weak`.
    namespace: Mutex<Weak<MountNamespace>>,
    /// The pin of the point this mount is attached at, while it is attached under another. Written
    /// under its namespace's `mutation` lock; its own lock is a leaf.
    pin: Mutex<Option<Pin>>,
    /// Its charge to the process that made it, that process's job and the broker, if a process
    /// made it.
    _quota: Option<QuotaReservation>,
}

/// Authorizes every lookup: for lookups the caller was already allowed to make, or that no caller
/// is checked for.
#[expect(
    clippy::unnecessary_wraps,
    reason = "a `Backend::resolve` authorization callback"
)]
pub(crate) fn allow_lookup(_: &PermissionInfo) -> Result<(), WalkError> {
    Ok(())
}

impl Mount {
    pub(crate) fn id(&self) -> MountId {
        self.id
    }

    pub(crate) fn info(&self) -> &MountInfo {
        &self.info
    }

    /// Whether writes through this mount fail.
    pub(crate) fn is_read_only(&self) -> bool {
        self.writes.load(Ordering::Acquire) & READ_ONLY != 0
    }

    /// Make writes through this mount fail, or succeed again. Fails with [`FileError::Busy`] if it
    /// would become read-only while a write is in progress through it or a file is open for writing
    /// on it, as Linux refuses then.
    pub(crate) fn set_read_only(&self, read_only: bool) -> FileResult<()> {
        if !read_only {
            self.writes.fetch_and(!READ_ONLY, Ordering::AcqRel);
            return Ok(());
        }
        match self
            .writes
            .compare_exchange(0, READ_ONLY, Ordering::AcqRel, Ordering::Acquire)
        {
            Err(writes) if writes & READ_ONLY == 0 => Err(FileError::Busy),
            Ok(_) | Err(_) => Ok(()),
        }
    }

    /// Start a write through this mount, which keeps it writable until the returned writer drops;
    /// `None` if it is read-only.
    pub(crate) fn begin_write(self: &Arc<Self>) -> Option<MountWriter> {
        self.writes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |writes| {
                (writes & READ_ONLY == 0).then_some(writes + 1)
            })
            .ok()?;
        Some(MountWriter(Arc::clone(self)))
    }

    /// How many open files, roots and working directories are on this mount.
    pub(crate) fn users(&self) -> usize {
        self.users.load(Ordering::Relaxed)
    }

    /// `path`, a path inside this mount, as a path inside its backend.
    pub(crate) fn backend_path(&self, path: &[String]) -> Vec<String> {
        self.backend_root.iter().chain(path).cloned().collect()
    }

    /// Pin `point`, a path inside this mount, where a mount is to be attached. Fails with
    /// [`FileError::Busy`] while a removal or rename is changing it or a directory above it.
    pub(crate) fn pin(&self, point: &[String]) -> FileResult<Pin> {
        self.family
            .points
            .pin(&self.backend, self.backend_path(point))
    }

    /// Reserve `paths`, paths inside this mount, for a removal or rename. Fails with
    /// [`FileError::Busy`] while a mount is attached at one of them, or, for those marked, below
    /// one.
    pub(crate) fn reserve(&self, paths: &[(&[String], bool)]) -> FileResult<Reservation> {
        let paths = paths
            .iter()
            .map(|(path, below)| (self.backend_path(path), *below))
            .collect();
        self.family.points.reserve(&self.backend, paths)
    }

    /// Take the pin of this mount's point, to give it to a mount that takes its place, while its
    /// namespace's `mutation` lock is held.
    pub(crate) fn take_pin(&self) -> Option<Pin> {
        self.pin.lock().take()
    }

    pub(crate) fn root(&self) -> &MountRoot {
        &self.root
    }

    /// The backend the mount shows, which its binds and copies share.
    pub(crate) fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// A snapshot of the tree this mount is attached to, or a tree of its own (with no parent and
    /// no children) if it is detached.
    pub(crate) fn tree(self: &Arc<Self>) -> Arc<MountTree> {
        let namespace = self.namespace.lock().clone();
        match namespace.upgrade() {
            Some(namespace) => namespace.tree(),
            None => Arc::new(MountTree::of(Arc::clone(self))),
        }
    }

    /// Resolve the mount's root, without search checks: a bind shows its source whether or not
    /// the caller could reach it. The root is never a symbolic link.
    pub(crate) fn resolve_root(&self) -> Result<ResolvedTarget<'_>, WalkError> {
        match &self.root {
            MountRoot::Backend => Ok(ResolvedTarget::Dir(self.backend.root()?)),
            MountRoot::Dir(dir) => {
                if let Some(dir) = self.backend.walking_dir_at(dir) {
                    return Ok(ResolvedTarget::Dir(dir));
                }
                match self.walk_backend(&self.backend_root)? {
                    Resolution::Found(ResolvedTarget::Dir(dir)) => Ok(ResolvedTarget::Dir(dir)),
                    _ => Err(PathError::NoSuchFileOrDirectory.into()),
                }
            }
            MountRoot::File { parent, name, node } => {
                let target = found(match self.backend.walking_dir_at(parent) {
                    Some(parent) => self
                        .backend
                        .resolve(parent, &[name.as_str()], &allow_lookup)
                        .map_err(|error| error.error)?,
                    None => self.walk_backend(&self.backend_root)?,
                })?;
                if bound_file_node(&*self.backend, &target)? != *node {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
                Ok(target)
            }
        }
    }

    /// Resolve `path`, a path inside this mount, as the path inside its backend that pins and
    /// reservations name, walked from the backend's root without search checks, unlike a location,
    /// whose anchor can name a directory that has since been removed or renamed.
    pub(crate) fn resolve_backend_path<R>(
        &self,
        path: &[String],
        found: impl for<'m> FnOnce(Resolution<'m>) -> R,
    ) -> Result<R, WalkError> {
        Ok(found(self.walk_backend(&self.backend_path(path))?))
    }

    /// Walk `components` from the backend's root without search checks.
    fn walk_backend(&self, components: &[String]) -> Result<Resolution<'_>, WalkError> {
        let components: Vec<&str> = components.iter().map(String::as_str).collect();
        self.backend
            .resolve(self.backend.root()?, &components, &allow_lookup)
            .map_err(|error| error.error)
    }
}

/// A node in a mount tree, as a path inside a mount.
///
/// Walks from a location start at its anchor, the directory at `path[..anchor_depth]`: through
/// `anchor`, an owned handle on it, when there is one; otherwise, or when the handle is stale (a
/// network backend), by walking `path[..anchor_depth]` from the mount's root without search checks.
/// They check search permission only from the anchor down, as Linux checks none of the ancestors
/// of a working directory, a root or an open directory. A walk keeps the anchor of the location it
/// started from while it stays at or below the anchor's depth.
#[derive(Clone)]
pub(crate) struct Location {
    pub(crate) mount: Arc<Mount>,
    pub(crate) path: Vec<String>,
    pub(crate) anchor: Option<DirHandle>,
    /// At most `path.len()`.
    pub(crate) anchor_depth: usize,
}

impl Location {
    /// The root of `mount`.
    pub(crate) fn root_of(mount: Arc<Mount>) -> Self {
        Self {
            mount,
            path: Vec::new(),
            anchor: None,
            anchor_depth: 0,
        }
    }

    /// `path` in `mount`, through `dir`, an owned handle on the directory there.
    pub(crate) fn anchored(mount: Arc<Mount>, path: Vec<String>, dir: DirHandle) -> Self {
        let anchor_depth = path.len();
        Self {
            mount,
            path,
            anchor: Some(dir),
            anchor_depth,
        }
    }

    /// `path` in `mount` without a handle, reached without walking its ancestors (by climbing out
    /// of a mount attached there, or opening a non-directory), so later walks don't check them
    /// either.
    pub(crate) fn unanchored(mount: Arc<Mount>, path: Vec<String>) -> Self {
        let anchor_depth = path.len();
        Self {
            mount,
            path,
            anchor: None,
            anchor_depth,
        }
    }

    /// Whether this is the same node of the same mount as `other`.
    pub(crate) fn is_at(&self, other: &Location) -> bool {
        Arc::ptr_eq(&self.mount, &other.mount) && self.path == other.path
    }
}

/// A location that counts as a user of its mount while it lives: an open file's, or a context's
/// root or working directory.
pub(crate) struct HeldLocation(Location);

impl HeldLocation {
    pub(crate) fn new(location: Location) -> Self {
        location.mount.users.fetch_add(1, Ordering::Relaxed);
        Self(location)
    }
}

impl Clone for HeldLocation {
    fn clone(&self) -> Self {
        Self::new(self.0.clone())
    }
}

impl core::ops::Deref for HeldLocation {
    type Target = Location;

    fn deref(&self) -> &Location {
        &self.0
    }
}

impl Drop for HeldLocation {
    fn drop(&mut self) {
        self.0.mount.users.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A write in progress through a mount, or a file open for writing on it, which keeps the mount
/// from becoming read-only while it lives.
pub(crate) struct MountWriter(Arc<Mount>);

impl Drop for MountWriter {
    fn drop(&mut self) {
        self.0.writes.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The mounts of a namespace and where they are attached.
#[derive(Clone)]
pub(crate) struct MountTree {
    root: Arc<Mount>,
    /// Each attached mount's parent and its point there, a path inside the parent.
    parents: HashMap<MountId, (Arc<Mount>, Vec<String>)>,
    /// The mount attached at each point of each mount: at most one per point, so mounts made on an
    /// occupied point stack in a chain, each on the root of the one below.
    children: HashMap<MountId, HashMap<Vec<String>, Arc<Mount>>>,
}

impl MountTree {
    /// A tree of `root` alone.
    fn of(root: Arc<Mount>) -> Self {
        Self {
            root,
            parents: HashMap::new(),
            children: HashMap::new(),
        }
    }

    pub(crate) fn root(&self) -> &Arc<Mount> {
        &self.root
    }

    /// The mount attached at `path` in `mount`.
    pub(crate) fn child(&self, mount: &Mount, path: &[String]) -> Option<&Arc<Mount>> {
        self.children.get(&mount.id)?.get(path)
    }

    /// The points in `mount` that have a mount attached.
    pub(crate) fn points(&self, mount: &Mount) -> impl Iterator<Item = &[String]> {
        self.children
            .get(&mount.id)
            .into_iter()
            .flat_map(|points| points.keys().map(Vec::as_slice))
    }

    /// The mount `mount` is attached to and its point there.
    pub(crate) fn parent(&self, mount: &Mount) -> Option<(&Arc<Mount>, &[String])> {
        let (parent, point) = self.parents.get(&mount.id)?;
        Some((parent, point))
    }

    /// Whether `mount` is in this tree.
    pub(crate) fn contains(&self, mount: &Arc<Mount>) -> bool {
        Arc::ptr_eq(mount, &self.root)
            || self
                .parent(mount)
                .and_then(|(parent, point)| self.child(parent, point))
                .is_some_and(|child| Arc::ptr_eq(child, mount))
    }

    /// Whether a mount is attached anywhere in `mount`, including on its root.
    pub(crate) fn has_children(&self, mount: &Mount) -> bool {
        self.children.contains_key(&mount.id)
    }

    /// The mounts attached in `mount`, at their points there.
    pub(crate) fn children(&self, mount: &Mount) -> impl Iterator<Item = (&[String], &Arc<Mount>)> {
        self.children.get(&mount.id).into_iter().flat_map(|points| {
            points
                .iter()
                .map(|(point, child)| (point.as_slice(), child))
        })
    }

    /// The top of the stack of mounts at `point` in `mount`, where a mount attached there goes:
    /// the root of the last mount stacked there, or the point itself if none is.
    pub(crate) fn top(&self, mount: &Arc<Mount>, point: &[String]) -> (Arc<Mount>, Vec<String>) {
        let (mut mount, mut point) = (Arc::clone(mount), point.to_vec());
        while let Some(child) = self.child(&mount, &point) {
            (mount, point) = (Arc::clone(child), Vec::new());
        }
        (mount, point)
    }

    /// `mount` and the mounts attached under it, each after the one it is attached to.
    pub(crate) fn subtree(&self, mount: &Arc<Mount>) -> Vec<Arc<Mount>> {
        let mut mounts = alloc::vec![Arc::clone(mount)];
        let mut next = 0;
        while let Some(parent) = mounts.get(next) {
            next += 1;
            let children: Vec<_> = self
                .children(parent)
                .map(|(_, child)| Arc::clone(child))
                .collect();
            mounts.extend(children);
        }
        mounts
    }

    fn insert(&mut self, parent: Arc<Mount>, point: Vec<String>, mount: Arc<Mount>) {
        self.children
            .entry(parent.id)
            .or_default()
            .insert(point.clone(), Arc::clone(&mount));
        self.parents.insert(mount.id, (parent, point));
    }

    /// Remove `mount` from where it is attached, keeping what is attached in it.
    fn unlink(&mut self, mount: &Mount) -> Option<(Arc<Mount>, Vec<String>)> {
        let (parent, point) = self.parents.remove(&mount.id)?;
        if let Some(points) = self.children.get_mut(&parent.id) {
            points.remove(&point);
            if points.is_empty() {
                self.children.remove(&parent.id);
            }
        }
        Some((parent, point))
    }

    /// The path of `location` from `root`, if `root` is at or above it.
    pub(crate) fn path_from(&self, root: &Location, location: &Location) -> Option<String> {
        let mut segments = Vec::new();
        let (mut mount, mut path) = (&location.mount, location.path.as_slice());
        loop {
            if Arc::ptr_eq(mount, &root.mount)
                && let Some(below) = path.strip_prefix(root.path.as_slice())
            {
                segments.push(below);
                break;
            }
            segments.push(path);
            (mount, path) = self.parent(mount)?;
        }
        let components = segments.iter().rev().flat_map(|segment| segment.iter());
        Some(absolute_path(components))
    }
}

/// `components` as an absolute path.
pub(crate) fn absolute_path<'a>(components: impl IntoIterator<Item = &'a String>) -> String {
    let path = components
        .into_iter()
        .fold(String::new(), |path, component| path + "/" + component);
    if path.is_empty() {
        String::from("/")
    } else {
        path
    }
}

/// A mount namespace: a tree of mounts.
///
/// Public only as an opaque handle, as a PID namespace is.
pub struct MountNamespace {
    #[expect(dead_code, reason = "namespace queries report it")]
    id: MountNamespaceId,
    family: Arc<MountFamily>,
    /// Builds and interprets the state of the files opened in this namespace.
    ops: Arc<dyn FileOps>,
    /// Hands out the devices of the backends mounted in this namespace.
    allocators: Arc<InodeAllocators>,
    /// Serializes changes to `tree`.
    mutation: Mutex<()>,
    /// Copied on write: readers clone the `Arc` and release the lock at once; writers build a new
    /// tree under `mutation` and swap it in.
    tree: RwLock<Arc<MountTree>>,
    /// Bumped by every change to `tree`, so an operation that resolved its operands before taking
    /// `mutation` can tell whether they still stand.
    generation: AtomicU64,
    /// Its charge to the process that created it, that process's job and the broker, if a process
    /// created it.
    _quota: Option<QuotaReservation>,
}

impl MountNamespace {
    /// A namespace whose root mount shows all of `backend`, whose files `ops` interprets, and whose
    /// new backends take their devices from `allocators`. Opens nothing.
    pub(crate) fn new(
        backend: Arc<dyn Backend>,
        ops: Arc<dyn FileOps>,
        allocators: Arc<InodeAllocators>,
    ) -> Arc<Self> {
        let family = MountFamily::new(Arc::clone(allocators.mount_points()));
        let root = Self::mount(
            &family,
            backend,
            MountRoot::Backend,
            Vec::new(),
            MountInfo::default(),
            None,
        );
        let namespace = Arc::new(Self {
            id: MountNamespaceId(family.next_id()),
            family,
            ops,
            allocators,
            mutation: Mutex::new(()),
            tree: RwLock::new(Arc::new(MountTree::of(Arc::clone(&root)))),
            generation: AtomicU64::new(0),
            _quota: None,
        });
        *root.namespace.lock() = Arc::downgrade(&namespace);
        namespace
    }

    fn mount(
        family: &Arc<MountFamily>,
        backend: Arc<dyn Backend>,
        root: MountRoot,
        backend_root: Vec<String>,
        info: MountInfo,
        quota: Option<QuotaReservation>,
    ) -> Arc<Mount> {
        Arc::new(Mount {
            id: MountId(family.next_id()),
            family: Arc::clone(family),
            backend,
            root,
            backend_root,
            writes: AtomicUsize::new(0),
            info,
            users: AtomicUsize::new(0),
            namespace: Mutex::new(Weak::new()),
            pin: Mutex::new(None),
            _quota: quota,
        })
    }

    /// Builds and interprets the state of the files opened in this namespace.
    pub(crate) fn ops(&self) -> &Arc<dyn FileOps> {
        &self.ops
    }

    /// Hands out the devices of the backends mounted in this namespace.
    pub(crate) fn allocators(&self) -> &Arc<InodeAllocators> {
        &self.allocators
    }

    /// A snapshot of the namespace's tree.
    pub(crate) fn tree(&self) -> Arc<MountTree> {
        Arc::clone(&self.tree.read())
    }

    /// How many changes the tree has had: take it before resolving the operands of a change.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// The root of the namespace's root mount.
    pub(crate) fn root(&self) -> Location {
        Location::root_of(Arc::clone(self.tree().root()))
    }

    /// Make a detached mount of `root` in `backend`, whose path inside the backend is
    /// `backend_root`, charged as `quota`, to attach to this namespace's tree.
    pub(crate) fn new_mount(
        &self,
        backend: Arc<dyn Backend>,
        root: MountRoot,
        backend_root: Vec<String>,
        info: MountInfo,
        quota: Option<QuotaReservation>,
    ) -> Arc<Mount> {
        Self::mount(&self.family, backend, root, backend_root, info, quota)
    }

    /// Make a detached copy of `mount`, showing the same node of the same backend, charged as
    /// `quota`, to attach to this namespace's tree.
    pub(crate) fn copy_mount(&self, mount: &Mount, quota: Option<QuotaReservation>) -> Arc<Mount> {
        let copy = self.new_mount(
            Arc::clone(&mount.backend),
            mount.root.clone(),
            mount.backend_root.clone(),
            mount.info.clone(),
            quota,
        );
        if mount.is_read_only() {
            copy.writes.store(READ_ONLY, Ordering::Release);
        }
        copy
    }

    /// A copy of this namespace, sharing its family: new mounts showing the same nodes, attached
    /// the same way, whose changes are their own, as Linux's `CLONE_NEWNS` copies a namespace.
    /// Returns it with the copies, to move locations onto, and what `capture` returns. The
    /// namespace and its mounts are charged to `process`, failing with `ResourceExhausted` if a
    /// count would exceed its limit.
    ///
    /// `capture` runs under `mutation` just before the tree is copied, so the locations it takes
    /// (a context's root and working directory, which a pivot moves under the same lock) are
    /// those of the tree copied. It must take no lock that is ever held while taking `mutation`.
    /// What it returns can keep a lock it took (the registry of contexts) past the copy; on
    /// failure, that drops first.
    pub(crate) fn copy<T>(
        &self,
        process: &BrokerProcess,
        capture: impl FnOnce() -> T,
    ) -> crate::Result<(Arc<Self>, MountCopies, T)> {
        let quota = process.charge_mount_namespace()?;
        let mut copies = HashMap::new();
        let mut pins = Vec::new();
        // Under `mutation`, every mount in the tree keeps the pin of its point, which no unmount
        // can release meanwhile, so the copies pin points that exist.
        let mutation = self.mutation.lock();
        let captured = capture();
        let new_tree = self.copy_tree(process, &mut copies, &mut pins);
        drop(mutation);
        // On failure, the partial copies, their pins and what was captured drop here, after the
        // lock.
        let new_tree = new_tree?;
        let namespace = Arc::new(Self {
            id: MountNamespaceId(self.family.next_id()),
            family: Arc::clone(&self.family),
            ops: Arc::clone(&self.ops),
            allocators: Arc::clone(&self.allocators),
            mutation: Mutex::new(()),
            tree: RwLock::new(Arc::new(new_tree)),
            generation: AtomicU64::new(0),
            _quota: Some(quota),
        });
        for (_, copy) in copies.values() {
            *copy.namespace.lock() = Arc::downgrade(&namespace);
        }
        for (copy, pin) in pins {
            *copy.pin.lock() = Some(pin);
        }
        Ok((namespace, MountCopies(copies), captured))
    }

    /// Copy the tree, under `mutation`, into a tree of copies charged to `process`, gathering the
    /// copies by their originals' identifiers into `copies` and their pins into `pins`, so they
    /// drop after the lock on failure. Copying a mount clones its root's handle, which makes no
    /// backend call (every backend's handles are reference-counted or plain data); dropping one
    /// may.
    fn copy_tree(
        &self,
        process: &BrokerProcess,
        copies: &mut HashMap<MountId, (Arc<Mount>, Arc<Mount>)>,
        pins: &mut Vec<(Arc<Mount>, Pin)>,
    ) -> crate::Result<MountTree> {
        let tree = self.tree();
        let root = self.copy_mount(tree.root(), Some(process.charge_mount()?));
        copies.insert(tree.root().id, (Arc::clone(tree.root()), Arc::clone(&root)));
        let mut new_tree = MountTree::of(root);
        for original in tree.subtree(tree.root()) {
            let parent = Arc::clone(&copies[&original.id].1);
            for (point, child) in tree.children(&original) {
                let copy = self.copy_mount(child, Some(process.charge_mount()?));
                copies.insert(child.id, (Arc::clone(child), Arc::clone(&copy)));
                let pin = self
                    .family
                    .points
                    .pin_again(&parent.backend, parent.backend_path(point));
                pins.push((Arc::clone(&copy), pin));
                new_tree.insert(Arc::clone(&parent), point.to_vec(), copy);
            }
        }
        Ok(new_tree)
    }

    /// Run `f` under `mutation`, so no change to the tree (and no pivot's move of contexts) happens
    /// meanwhile. `f` must take no lock that is ever held while taking `mutation`, and make no
    /// backend call or final drop of a mount or location.
    pub(crate) fn under_mutation<R>(&self, f: impl FnOnce() -> R) -> R {
        let _mutation = self.mutation.lock();
        f()
    }

    /// Change the tree with `change`, under `mutation`, if it hasn't changed since `generation`
    /// (or whatever happened, with `None`); `None` if it has, so the caller resolves its operands
    /// again. The change commits only if `change` succeeds; what it replaces drops after the lock
    /// is released.
    pub(crate) fn change<R>(
        self: &Arc<Self>,
        generation: Option<u64>,
        change: impl FnOnce(&mut TreeChange) -> FileResult<R>,
    ) -> Option<FileResult<R>> {
        let mutation = self.mutation.lock();
        if generation.is_some_and(|generation| generation != self.generation()) {
            return None;
        }
        let current = self.tree();
        let mut tree_change = TreeChange {
            tree: MountTree::clone(&current),
            attached: Vec::new(),
            moved: Vec::new(),
            detached: Vec::new(),
            changed: false,
        };
        let result = change(&mut tree_change);
        let TreeChange {
            tree,
            attached,
            moved,
            detached,
            changed,
        } = tree_change;
        let mut replaced_pins = Vec::new();
        let replaced = if result.is_ok() && changed {
            for (mount, pin) in attached {
                *mount.namespace.lock() = Arc::downgrade(self);
                replaced_pins.extend(mount.pin.lock().replace(pin));
            }
            for (mount, pin) in moved {
                replaced_pins.extend(core::mem::replace(&mut *mount.pin.lock(), pin));
            }
            for mount in &detached {
                *mount.namespace.lock() = Weak::new();
                replaced_pins.extend(mount.pin.lock().take());
            }
            Some(self.replace_tree(tree))
        } else {
            None
        };
        drop(mutation);
        drop((replaced, replaced_pins, detached, current));
        Some(result)
    }

    /// Attach the detached `mount` at `point` in `parent`, on top of any mounts already stacked
    /// there. Fails with [`FileError::InvalidArgument`] if `parent` is not in this namespace or
    /// `mount` is attached, and with [`FileError::Busy`] if a removal or rename is changing the
    /// point.
    #[cfg_attr(not(test), expect(dead_code, reason = "tests build trees with it"))]
    pub(crate) fn attach(
        self: &Arc<Self>,
        parent: &Arc<Mount>,
        point: Vec<String>,
        mount: Arc<Mount>,
    ) -> FileResult<()> {
        self.change(None, |change| {
            if !change.tree().contains(parent) || mount.namespace.lock().strong_count() != 0 {
                return Err(FileError::InvalidArgument);
            }
            let (parent, point) = change.tree().top(parent, &point);
            let pin = parent.pin(&point)?;
            change.attach(parent, point, mount, pin);
            Ok(())
        })
        .expect("a change without a generation always runs")
    }

    /// Detach `mount` and the mounts attached under it, each of which becomes a tree of its own.
    /// Fails with [`FileError::InvalidArgument`] if `mount` is this namespace's root mount or not
    /// in it.
    #[cfg_attr(not(test), expect(dead_code, reason = "tests build trees with it"))]
    pub(crate) fn detach(self: &Arc<Self>, mount: &Arc<Mount>) -> FileResult<()> {
        self.change(None, |change| change.detach(mount))
            .expect("a change without a generation always runs")
    }

    /// Swap in `tree`, returning the replaced one for the caller to drop outside its locks.
    fn replace_tree(&self, tree: MountTree) -> Arc<MountTree> {
        let replaced = core::mem::replace(&mut *self.tree.write(), Arc::new(tree));
        self.generation.fetch_add(1, Ordering::Release);
        replaced
    }
}

impl Drop for MountNamespace {
    fn drop(&mut self) {
        // The mounts of a namespace that ends are attached nowhere, whatever still holds them.
        let pins: Vec<Pin> = self
            .tree
            .get_mut()
            .children
            .values()
            .flat_map(HashMap::values)
            .filter_map(|mount| mount.pin.lock().take())
            .collect();
        drop(pins);
    }
}

/// The copies of the mounts of a namespace, by the originals' identifiers.
pub(crate) struct MountCopies(HashMap<MountId, (Arc<Mount>, Arc<Mount>)>);

impl MountCopies {
    /// `location`, moved onto the copy of its mount if that is one of the copied namespace's.
    pub(crate) fn moved(&self, location: &Location) -> Location {
        match self.0.get(&location.mount.id) {
            Some((original, copy)) if Arc::ptr_eq(original, &location.mount) => Location {
                mount: Arc::clone(copy),
                ..location.clone()
            },
            _ => location.clone(),
        }
    }
}

/// A change to a namespace's tree, made under its `mutation` lock to a copy of the tree, with what
/// to do to the mounts it attaches, moves and detaches once it commits.
pub(crate) struct TreeChange {
    tree: MountTree,
    attached: Vec<(Arc<Mount>, Pin)>,
    moved: Vec<(Arc<Mount>, Option<Pin>)>,
    detached: Vec<Arc<Mount>>,
    /// Whether the tree changed, so a change that only checked it commits nothing.
    changed: bool,
}

impl TreeChange {
    /// The tree as changed so far.
    pub(crate) fn tree(&self) -> &MountTree {
        &self.tree
    }

    /// Attach the detached `mount` at `point` in `parent`, the top of the stack there, whose pin is
    /// `pin`.
    pub(crate) fn attach(
        &mut self,
        parent: Arc<Mount>,
        point: Vec<String>,
        mount: Arc<Mount>,
        pin: Pin,
    ) {
        debug_assert!(self.tree.child(&parent, &point).is_none());
        self.tree.insert(parent, point, Arc::clone(&mount));
        self.attached.push((mount, pin));
        self.changed = true;
    }

    /// Move `mount`, with what is attached in it, to `point` in `parent`, the top of the stack
    /// there, whose pin is `pin`, or make it the root of the tree if `parent` is `None`.
    pub(crate) fn move_mount(
        &mut self,
        mount: &Arc<Mount>,
        parent: Option<(Arc<Mount>, Vec<String>)>,
        pin: Option<Pin>,
    ) {
        self.tree.unlink(mount);
        match parent {
            Some((parent, point)) => {
                debug_assert!(self.tree.child(&parent, &point).is_none());
                self.tree.insert(parent, point, Arc::clone(mount));
            }
            None => self.tree.root = Arc::clone(mount),
        }
        self.moved.push((Arc::clone(mount), pin));
        self.changed = true;
    }

    /// Detach `mount` and the mounts attached under it, each of which becomes a tree of its own.
    /// Fails with [`FileError::InvalidArgument`] if `mount` is the tree's root mount or not in it.
    pub(crate) fn detach(&mut self, mount: &Arc<Mount>) -> FileResult<()> {
        if Arc::ptr_eq(mount, &self.tree.root) || !self.tree.contains(mount) {
            return Err(FileError::InvalidArgument);
        }
        let detached = self.tree.subtree(mount);
        for detaching in &detached {
            self.tree.unlink(detaching);
        }
        self.detached.extend(detached);
        self.changed = true;
        Ok(())
    }
}
