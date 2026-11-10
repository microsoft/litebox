// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mount trees: the mounts of a mount namespace, and the [`Location`]s in them that path
//! resolution walks.
//!
//! A mount shows a backend, or one of its directories or files (a bind), at a point of its parent
//! mount. A namespace's mounts form a tree, which is copied on write: readers take a snapshot (an
//! `Arc` clone) and walk it without holding a lock, so no lock here is ever held across a backend
//! call. Mount types, sources and options are opaque strings to the core.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use hashbrown::HashMap;
use litebox_broker_protocol::fs::FileError;
use spin::{Mutex, RwLock};

use super::backend::{Backend, DirHandle, PermissionInfo, Resolution, ResolvedTarget};
use super::errors::{FileStatusError, PathError, WalkError};
use super::service::FileOps;
use super::{FileResult, FileType};

/// Identifies a mount. Never reused among the mounts of a namespace and the namespaces copied from
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MountId(u64);

/// Identifies a mount namespace, like [`MountId`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct MountNamespaceId(u64);

/// Hands out the identifiers of a namespace's mounts, and of namespaces copied from it.
#[derive(Debug)]
struct MountIds(AtomicU64);

impl MountIds {
    fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// What a mount shows at its root.
pub(crate) enum MountRoot {
    /// The whole backend, walked from [`Backend::root`].
    Backend,
    /// A directory of the backend (a bind), through an owned handle opened when the mount was made.
    #[cfg_attr(not(test), expect(dead_code, reason = "binds make it"))]
    Dir(DirHandle),
    /// A non-directory, non-symlink node of the backend (a file bind), found by looking `name` up in
    /// `parent`. The node there must still be the one bound, `node` (its device and inode numbers),
    /// as the mount can't hold the node itself.
    #[cfg_attr(not(test), expect(dead_code, reason = "binds make it"))]
    File {
        parent: DirHandle,
        name: String,
        node: (u64, u64),
    },
}

impl MountRoot {
    /// The root of a bind of the node `name` in `parent`, a directory of `backend`. Fails with
    /// [`PathError::NoSuchFileOrDirectory`] if the node is missing, a directory or a symbolic link.
    #[cfg_attr(not(test), expect(dead_code, reason = "binds make it"))]
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

/// A mount's type, source and options, as given when it was made. Opaque to the core.
#[derive(Clone, Debug, Default)]
#[expect(dead_code, reason = "mount queries report it")]
pub(crate) struct MountInfo {
    pub(crate) fs_type: String,
    pub(crate) source: String,
    pub(crate) options: String,
}

/// A backend, or a node of one, shown in a mount tree.
pub(crate) struct Mount {
    id: MountId,
    /// Shared by binds of the backend and by copies of the mount.
    backend: Arc<dyn Backend>,
    root: MountRoot,
    /// The root's path inside the backend, used when the root's handle is stale.
    backend_root: Vec<String>,
    #[expect(dead_code, reason = "read-only mounts and their queries use it")]
    read_only: AtomicBool,
    #[expect(dead_code, reason = "mount queries report it")]
    info: MountInfo,
    /// Open files, and roots and working directories, on this mount, which keep it busy: the
    /// [`HeldLocation`]s on it.
    users: AtomicUsize,
    /// The namespace whose tree this mount is attached to; dangling when it is detached. Written
    /// under that namespace's `mutation` lock; its own lock is held only to clone the `Weak`.
    namespace: Mutex<Weak<MountNamespace>>,
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
    /// How many open files, roots and working directories are on this mount.
    #[cfg_attr(not(test), expect(dead_code, reason = "unmount checks it"))]
    pub(crate) fn users(&self) -> usize {
        self.users.load(Ordering::Relaxed)
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

    fn contains(&self, mount: &Arc<Mount>) -> bool {
        Arc::ptr_eq(mount, &self.root)
            || self
                .parent(mount)
                .and_then(|(parent, point)| self.child(parent, point))
                .is_some_and(|child| Arc::ptr_eq(child, mount))
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
pub(crate) struct MountNamespace {
    #[expect(dead_code, reason = "namespace queries report it")]
    id: MountNamespaceId,
    ids: Arc<MountIds>,
    /// Builds and interprets the state of the files opened in this namespace.
    ops: Arc<dyn FileOps>,
    /// Serializes changes to `tree`.
    mutation: Mutex<()>,
    /// Copied on write: readers clone the `Arc` and release the lock at once; writers build a new
    /// tree under `mutation` and swap it in.
    tree: RwLock<Arc<MountTree>>,
    /// Bumped by every change to `tree`.
    generation: AtomicU64,
}

impl MountNamespace {
    /// A namespace whose root mount shows all of `backend`, whose files `ops` interprets. Opens
    /// nothing.
    pub(crate) fn new(backend: Arc<dyn Backend>, ops: Arc<dyn FileOps>) -> Arc<Self> {
        let ids = Arc::new(MountIds(AtomicU64::new(1)));
        let root = Self::mount(
            &ids,
            backend,
            MountRoot::Backend,
            Vec::new(),
            MountInfo::default(),
        );
        let namespace = Arc::new(Self {
            id: MountNamespaceId(ids.next()),
            ids,
            ops,
            mutation: Mutex::new(()),
            tree: RwLock::new(Arc::new(MountTree::of(Arc::clone(&root)))),
            generation: AtomicU64::new(0),
        });
        *root.namespace.lock() = Arc::downgrade(&namespace);
        namespace
    }

    fn mount(
        ids: &MountIds,
        backend: Arc<dyn Backend>,
        root: MountRoot,
        backend_root: Vec<String>,
        info: MountInfo,
    ) -> Arc<Mount> {
        Arc::new(Mount {
            id: MountId(ids.next()),
            backend,
            root,
            backend_root,
            read_only: AtomicBool::new(false),
            info,
            users: AtomicUsize::new(0),
            namespace: Mutex::new(Weak::new()),
        })
    }

    /// Builds and interprets the state of the files opened in this namespace.
    pub(crate) fn ops(&self) -> &Arc<dyn FileOps> {
        &self.ops
    }

    /// A snapshot of the namespace's tree.
    pub(crate) fn tree(&self) -> Arc<MountTree> {
        Arc::clone(&self.tree.read())
    }

    /// The root of the namespace's root mount.
    pub(crate) fn root(&self) -> Location {
        Location::root_of(Arc::clone(self.tree().root()))
    }

    /// Make a detached mount of `root` in `backend`, whose path inside the backend is
    /// `backend_root`, to attach to this namespace's tree.
    #[cfg_attr(not(test), expect(dead_code, reason = "mount operations use it"))]
    pub(crate) fn new_mount(
        &self,
        backend: Arc<dyn Backend>,
        root: MountRoot,
        backend_root: Vec<String>,
        info: MountInfo,
    ) -> Arc<Mount> {
        Self::mount(&self.ids, backend, root, backend_root, info)
    }

    /// Attach the detached `mount` at `point` in `parent`, on top of any mounts already stacked
    /// there. Fails with [`FileError::InvalidArgument`] if `parent` is not in this namespace or
    /// `mount` is attached.
    #[cfg_attr(not(test), expect(dead_code, reason = "mount operations use it"))]
    pub(crate) fn attach(
        self: &Arc<Self>,
        parent: &Arc<Mount>,
        point: Vec<String>,
        mount: Arc<Mount>,
    ) -> FileResult<()> {
        let mutation = self.mutation.lock();
        let tree = self.tree();
        if !tree.contains(parent) || mount.namespace.lock().strong_count() != 0 {
            return Err(FileError::InvalidArgument);
        }
        let (mut parent, mut point) = (Arc::clone(parent), point);
        while let Some(top) = tree.child(&parent, &point) {
            (parent, point) = (Arc::clone(top), Vec::new());
        }
        let mut changed = MountTree::clone(&tree);
        changed
            .children
            .entry(parent.id)
            .or_default()
            .insert(point.clone(), Arc::clone(&mount));
        changed.parents.insert(mount.id, (parent, point));
        *mount.namespace.lock() = Arc::downgrade(self);
        let replaced = self.replace_tree(changed);
        drop(mutation);
        drop(replaced);
        Ok(())
    }

    /// Detach `mount` and the mounts attached under it, each of which becomes a tree of its own.
    /// Fails with [`FileError::InvalidArgument`] if `mount` is this namespace's root mount or not
    /// in it.
    #[cfg_attr(not(test), expect(dead_code, reason = "mount operations use it"))]
    pub(crate) fn detach(&self, mount: &Arc<Mount>) -> FileResult<()> {
        let mutation = self.mutation.lock();
        let tree = self.tree();
        if Arc::ptr_eq(mount, &tree.root) || !tree.contains(mount) {
            return Err(FileError::InvalidArgument);
        }
        let mut changed = MountTree::clone(&tree);
        let (parent, point) = changed
            .parents
            .remove(&mount.id)
            .expect("attached mounts have a parent");
        if let Some(points) = changed.children.get_mut(&parent.id) {
            points.remove(&point);
            if points.is_empty() {
                changed.children.remove(&parent.id);
            }
        }
        let mut detached = alloc::vec![Arc::clone(mount)];
        let mut next = 0;
        while let Some(detaching) = detached.get(next) {
            next += 1;
            if let Some(points) = changed.children.remove(&detaching.id) {
                for child in points.into_values() {
                    changed.parents.remove(&child.id);
                    detached.push(child);
                }
            }
        }
        for detaching in &detached {
            *detaching.namespace.lock() = Weak::new();
        }
        let replaced = self.replace_tree(changed);
        drop(mutation);
        drop((replaced, parent, detached));
        Ok(())
    }

    /// Swap in `tree`, returning the replaced one for the caller to drop outside its locks.
    fn replace_tree(&self, tree: MountTree) -> Arc<MountTree> {
        let replaced = core::mem::replace(&mut *self.tree.write(), Arc::new(tree));
        self.generation.fetch_add(1, Ordering::Relaxed);
        replaced
    }
}
