// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Mount operations of a thread: mounting a backend, binding a node, making a mount read-only,
//! unmounting, pivoting the root of its mount namespace, and changing its root and working
//! directory.
//!
//! Operations that change a mount tree (mount and bind targets, bind sources, read-only changes,
//! unmounts and pivots) take only mounts of the calling thread's namespace, and fail with
//! [`FileError::InvalidArgument`] otherwise; changing a root or a working directory takes any
//! directory, including one on a mount of another namespace or a detached one, as Linux's
//! `fchdir` does.
//!
//! Each operation resolves its operands, then changes the tree only if no other change happened
//! meanwhile, and resolves them again otherwise. Attaching a mount first pins its point, so no
//! removal or rename can start on it, then checks, without holding a lock, that the point still
//! exists as the same kind of node.
//!
//! Each new mount, including the copies a recursive bind makes, is charged to the calling process,
//! its job and the broker until it drops, and an operation that would exceed a limit of
//! [`BrokerCoreLimits`](crate::BrokerCoreLimits) fails with [`BrokerError::ResourceExhausted`].
//!
//! The core knows no Linux flags: the shim decodes `mount`, `umount2` and `pivot_root` into these.
//!
//! Differences from Linux: a mount point can't be removed or renamed, nor can a directory above
//! one be renamed, through any mount or namespace that shows it (Linux moves the mounts below a
//! renamed directory, and since 3.18 lazily unmounts those on a node removed through another
//! namespace); mounts don't propagate (no shared or slave mounts); a file bind shows the node it
//! was made of only while that node keeps its name; and nothing can be mounted in a bind of a
//! directory that has since been removed or renamed, as mount points are paths inside backends.
//!
//! A backend that enforces permissions itself (9P) checks search permission on a directory, by its
//! own rules, only when a name is looked up in it, and 9P can't be asked whether a directory may be
//! searched. So on such a backend, changing the root or working directory to a directory, and `.`
//! and `..` steps from one, don't check search permission on it as Linux does (lookups of names in
//! it still are checked); and `..` above a location's anchor walks again from its mount's root, and
//! a file bind's root is found by looking its name up in its parent, so both need the backend to
//! allow searching the directories walked, where Linux checks none.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use litebox_broker_protocol::fs::{FileError, FileMode, FileUser};
use litebox_broker_protocol::{ObjectHandle, ThreadId};

use super::backend::{Backend, Resolution, ResolvedTarget};
use super::context::{FsContext, FsContextSnapshot};
use super::mount::{Location, Mount, MountInfo, MountNamespace, MountRoot, MountTree, Pin};
use super::resolver::{can_search, resolve_from, resolve_location};
use super::service::{file_walk_error, file_with_any_rights};
use super::{FileResult, OFlags};
use crate::object::ObjectRights;
use crate::quota::QuotaReservation;
use crate::{BrokerError, BrokerProcess, Result};

/// A node that a mount operation names: `path`, resolved in the calling thread's file-system
/// context, relative paths from `base` if given; or `base` itself if `path` is empty.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountPath<'a> {
    /// An open file that relative paths start from, or that the operation names itself if `path`
    /// is empty.
    pub base: Option<ObjectHandle>,
    /// The path.
    pub path: &'a str,
}

impl<'a> MountPath<'a> {
    /// `path`, relative paths from the calling thread's working directory.
    #[must_use]
    pub const fn path(path: &'a str) -> Self {
        Self { base: None, path }
    }

    /// The open file `handle` itself.
    #[must_use]
    pub const fn handle(handle: ObjectHandle) -> Self {
        Self {
            base: Some(handle),
            path: "",
        }
    }
}

/// What a new mount shows.
pub enum NewMount {
    /// A new, empty in-memory file system, whose root directory has `mode` and `owner`.
    Tmpfs {
        /// The root directory's permission bits.
        mode: FileMode,
        /// The root directory's owner.
        owner: FileUser,
    },
    /// All of a backend.
    Backend(Arc<dyn Backend>),
}

/// Mount `source` on the directory `target`, on top of any mounts already stacked there, with the
/// type, source and options `info` and, if `read_only`, refusing writes.
///
/// Fails with [`FileError::NotDirectory`] if the target isn't a directory, and with
/// [`FileError::Busy`] if a removal or rename is changing it.
pub fn mount(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
    source: NewMount,
    info: MountInfo,
    read_only: bool,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let caller = Caller::of(process, thread)?;
    let backend = match source {
        NewMount::Tmpfs { mode, owner } => match tmpfs(&caller.namespace, mode, owner) {
            Ok(backend) => backend,
            Err(error) => return Ok(Err(error)),
        },
        NewMount::Backend(backend) => backend,
    };
    let mount = caller.namespace.new_mount(
        backend,
        MountRoot::Backend,
        Vec::new(),
        info,
        Some(process.charge_mount()?),
    );
    if read_only {
        mount
            .set_read_only(true)
            .map_err(|_| BrokerError::Internal)?;
    }
    loop {
        let generation = caller.namespace.generation();
        let attachment = match caller.attachment(process, user, target, Kind::Dir)? {
            Ok(attachment) => attachment,
            Err(error) => return Ok(Err(error)),
        };
        let mount = Arc::clone(&mount);
        if let Some(result) = caller.namespace.change(Some(generation), |change| {
            attachment.commit(change, mount, Vec::new())
        }) {
            return Ok(result);
        }
    }
}

/// Bind the node `source` onto `target`, a file onto a file or a directory onto a directory, on
/// top of any mounts already stacked there; with `recursive`, also copy the mounts attached at
/// or below the source onto the new mount first.
///
/// Fails with [`FileError::NotDirectory`] if only one of them is a directory, and with
/// [`FileError::Busy`] if a removal or rename is changing the target.
pub fn bind(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    source: MountPath<'_>,
    target: MountPath<'_>,
    recursive: bool,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let caller = Caller::of(process, thread)?;
    loop {
        let generation = caller.namespace.generation();
        let found = match caller.find(process, user, source, false)? {
            Ok(found) => found,
            Err(error) => return Ok(Err(error)),
        };
        let tree = caller.namespace.tree();
        if !tree.contains(&found.location.mount) {
            return Ok(Err(FileError::InvalidArgument));
        }
        let quota = process.charge_mount()?;
        let mount = match bind_mount(&caller.namespace, &found, quota) {
            Ok(mount) => mount,
            Err(error) => return Ok(Err(error)),
        };
        let attachment = match caller.attachment(process, user, target, found.kind)? {
            Ok(attachment) => attachment,
            Err(error) => return Ok(Err(error)),
        };
        let below = if recursive {
            match copy_below(process, &caller.namespace, &tree, &found.location, &mount)? {
                Ok(below) => below,
                Err(error) => return Ok(Err(error)),
            }
        } else {
            Vec::new()
        };
        if let Some(result) = caller.namespace.change(Some(generation), |change| {
            attachment.commit(change, mount, below)
        }) {
            return Ok(result);
        }
    }
}

/// Make writes through the mount whose root `target` names fail, or succeed again.
///
/// Fails with [`FileError::InvalidArgument`] if `target` isn't a mount's root, and with
/// [`FileError::Busy`] if the mount would become read-only while a write is in progress through it
/// or a file is open for writing on it.
pub fn set_read_only(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
    read_only: bool,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let caller = Caller::of(process, thread)?;
    loop {
        let generation = caller.namespace.generation();
        let mount = match caller.mount_root(process, user, target, false)? {
            Ok(mount) => mount,
            Err(error) => return Ok(Err(error)),
        };
        if let Some(result) = caller.namespace.change(Some(generation), |change| {
            if !change.tree().contains(&mount) {
                return Err(FileError::InvalidArgument);
            }
            mount.set_read_only(read_only)
        }) {
            return Ok(result);
        }
    }
}

/// Unmount the topmost mount stacked on the node `target` names, which may be the base itself or
/// `.`, as Linux's `umount2` finds it; with `detach`, also the mounts attached under it, each of
/// which becomes a tree of its own, so open files and contexts on them keep working, but `..` stops
/// at their roots.
///
/// Fails with [`FileError::InvalidArgument`] if the node isn't a mount's root or is the root mount of
/// the namespace, and, without `detach`, with [`FileError::Busy`] if a mount is attached in the
/// mount, including on its root, or a file is open on it or a root or working directory is on it.
pub fn unmount(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
    detach: bool,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let caller = Caller::of(process, thread)?;
    loop {
        let generation = caller.namespace.generation();
        let mount = match caller.mount_root(process, user, target, true)? {
            Ok(mount) => mount,
            Err(error) => return Ok(Err(error)),
        };
        if let Some(result) = caller.namespace.change(Some(generation), |change| {
            if !detach
                && change.tree().contains(&mount)
                && (change.tree().has_children(&mount) || mount.users() != 0)
            {
                return Err(FileError::Busy);
            }
            change.detach(&mount)
        }) {
            return Ok(result);
        }
    }
}

/// Make the directory `new_root`, the root of a mount below the caller's root, the root of the
/// caller's mount namespace in place of the caller's root mount, which moves to `put_old`, at or
/// below the new root, as Linux's `pivot_root` does. The new root's mount takes the old root
/// mount's place: its point in its parent, or the namespace's root if it was that. Every root and
/// working directory at the old root, in any process and namespace, moves to the new root.
///
/// With both the new root and `put_old` the caller's working directory, a mount root,
/// (`pivot_root(".", ".")`), the old root mount is stacked on the new root's root.
///
/// Fails, checking in Linux's order, with [`FileError::NotDirectory`] if an operand isn't a
/// directory; with [`FileError::InvalidArgument`] if a mount isn't in the caller's namespace; with
/// [`FileError::Busy`] if the new root, or the mount on top at `put_old`, is on the caller's root
/// mount; and with [`FileError::InvalidArgument`] if the caller's root isn't its mount's root, if
/// the new root isn't a mount's root below the caller's root, or if `put_old` isn't at or below the
/// new root.
pub fn pivot_root(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    new_root: MountPath<'_>,
    put_old: MountPath<'_>,
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WRITE)?;
    let mut caller = Caller::of(process, thread)?;
    loop {
        let generation = caller.namespace.generation();
        caller.snapshot = caller.context.snapshot();
        let pivot = match caller.pivot(process, user, new_root, put_old)? {
            Ok(pivot) => pivot,
            Err(error) => return Ok(Err(error)),
        };
        let core = &process.core;
        if let Some(result) = caller
            .namespace
            .change(Some(generation), |change| Ok(pivot.commit(change, core)))
        {
            // What the contexts held drops here, outside the namespace's lock.
            return Ok(result.map(drop));
        }
    }
}

/// Make the directory `target`, on any mount, the working directory of the calling thread's
/// file-system context.
///
/// Fails with [`FileError::NotDirectory`] if it isn't a directory, and with
/// [`FileError::NoSearchPermissions`] if `user` may not search it (unchecked on a backend that
/// enforces permissions itself: see the [module docs](self)).
pub fn change_directory(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
) -> Result<FileResult<()>> {
    change_context(process, thread, user, target, FsContext::set_cwd)
}

/// Make the directory `target`, on any mount, the root of the calling thread's file-system
/// context, where absolute paths start and above which `..` doesn't climb. The working directory
/// stays, as Linux's `chroot` leaves it.
///
/// Fails as [`change_directory`] does.
pub fn change_root(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
) -> Result<FileResult<()>> {
    change_context(process, thread, user, target, FsContext::set_root)
}

fn change_context(
    process: &BrokerProcess,
    thread: ThreadId,
    user: FileUser,
    target: MountPath<'_>,
    change: impl FnOnce(&FsContext, Location),
) -> Result<FileResult<()>> {
    process.require_object_rights(ObjectRights::WAIT)?;
    let caller = Caller::of(process, thread)?;
    let found = match caller.find(process, user, target, false)? {
        Ok(found) => found,
        Err(error) => return Ok(Err(error)),
    };
    if found.kind != Kind::Dir {
        return Ok(Err(FileError::NotDirectory));
    }
    // Keep an open handle on the directory, from which lookups start.
    let backend = Arc::clone(found.location.mount.backend());
    let dir = resolve_location(&found.location, |resolution| match resolution {
        Resolution::Found(ResolvedTarget::Dir(dir)) => {
            if !can_search(user, &dir.permissions) {
                return Err(FileError::NoSearchPermissions);
            }
            backend
                .open_dir(dir, OFlags::PATH)
                .map_err(|_| FileError::NoSuchFileOrDirectory)
        }
        _ => Err(FileError::NoSuchFileOrDirectory),
    });
    let dir = match dir
        .map_err(file_walk_error)
        .and_then(core::convert::identity)
    {
        Ok(dir) => dir,
        Err(error) => return Ok(Err(error)),
    };
    let location = Location::anchored(
        Arc::clone(&found.location.mount),
        found.location.path.clone(),
        dir,
    );
    change(&caller.context, location);
    Ok(Ok(()))
}

/// What a node is, as far as mounts go: a directory, or anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Dir,
    File,
}

impl Kind {
    fn of(resolution: &Resolution<'_>) -> Option<Self> {
        match resolution {
            Resolution::Found(ResolvedTarget::Dir(_)) => Some(Self::Dir),
            Resolution::Found(ResolvedTarget::File(_)) => Some(Self::File),
            Resolution::MissingFinal { .. } => None,
        }
    }

    fn of_root(mount: &Mount) -> Self {
        match mount.root() {
            MountRoot::File { .. } => Self::File,
            MountRoot::Backend | MountRoot::Dir(_) => Self::Dir,
        }
    }
}

/// A node a mount operation found.
struct Found {
    location: Location,
    kind: Kind,
}

/// The calling thread's file-system context, as of when the operation started.
struct Caller {
    context: Arc<FsContext>,
    namespace: Arc<MountNamespace>,
    snapshot: FsContextSnapshot,
}

impl Caller {
    /// The context of the thread `thread`. Fails with `UnknownObject` if the process has no such
    /// thread, and with `UnsupportedOperation` if it has no file system.
    fn of(process: &BrokerProcess, thread: ThreadId) -> Result<Self> {
        let context = process
            .fs_context(Some(thread))?
            .ok_or(BrokerError::UnsupportedOperation)?;
        let snapshot = context.snapshot();
        Ok(Self {
            namespace: Arc::clone(&snapshot.namespace),
            context,
            snapshot,
        })
    }

    /// Find the node `path` names for `user`, following symbolic links. With `top`, the node
    /// found is the root of the topmost mount stacked on it, if any is, even if it is the start
    /// of the walk, as Linux's `LOOKUP_MOUNTPOINT` finds it.
    fn find(
        &self,
        process: &BrokerProcess,
        user: FileUser,
        path: MountPath<'_>,
        top: bool,
    ) -> Result<FileResult<Found>> {
        if path.path.contains('\0') {
            return Ok(Err(FileError::InvalidPathname));
        }
        let base = match path.base {
            Some(handle) => {
                file_with_any_rights(process, handle, ObjectRights::WAIT | ObjectRights::WRITE)?
                    .location()
                    .clone()
            }
            None if path.path.is_empty() => return Ok(Err(FileError::NoSuchFileOrDirectory)),
            None => self.snapshot.cwd.clone(),
        };
        let found = if path.path.is_empty() {
            resolve_location(&base, |resolution| Kind::of(&resolution)).map(|kind| (base, kind))
        } else {
            resolve_from(
                user,
                &self.snapshot.root,
                &base,
                path.path,
                true,
                |location, resolution| (location.clone(), Kind::of(&resolution)),
            )
        };
        let (location, kind) = match found {
            Ok((location, Some(kind))) => (location, kind),
            Ok((_, None)) => return Ok(Err(FileError::NoSuchFileOrDirectory)),
            Err(error) => return Ok(Err(file_walk_error(error))),
        };
        if top {
            let (mount, _) = location.mount.tree().top(&location.mount, &location.path);
            if !Arc::ptr_eq(&mount, &location.mount) {
                return Ok(Ok(Found {
                    kind: Kind::of_root(&mount),
                    location: Location::root_of(mount),
                }));
            }
        }
        Ok(Ok(Found { location, kind }))
    }

    /// Find the mount whose root `path` names, as [`Self::find`] does. Fails with
    /// [`FileError::InvalidArgument`] if the node isn't a mount's root.
    fn mount_root(
        &self,
        process: &BrokerProcess,
        user: FileUser,
        path: MountPath<'_>,
        top: bool,
    ) -> Result<FileResult<Arc<Mount>>> {
        Ok(self.find(process, user, path, top)?.and_then(|found| {
            if found.location.path.is_empty() {
                Ok(found.location.mount)
            } else {
                Err(FileError::InvalidArgument)
            }
        }))
    }

    /// Find where a mount of a node of kind `kind` attaches on the node `target` names, pinned,
    /// and check that the node still exists.
    fn attachment(
        &self,
        process: &BrokerProcess,
        user: FileUser,
        target: MountPath<'_>,
        kind: Kind,
    ) -> Result<FileResult<Attachment>> {
        let found = match self.find(process, user, target, false)? {
            Ok(found) => found,
            Err(error) => return Ok(Err(error)),
        };
        if found.kind != kind {
            return Ok(Err(FileError::NotDirectory));
        }
        let tree = self.namespace.tree();
        if !tree.contains(&found.location.mount) {
            return Ok(Err(FileError::InvalidArgument));
        }
        let (parent, point) = tree.top(&found.location.mount, &found.location.path);
        let pin = match parent.pin(&point) {
            Ok(pin) => pin,
            Err(error) => return Ok(Err(error)),
        };
        if let Err(error) = expect_point(&parent, &point, kind) {
            return Ok(Err(error));
        }
        Ok(Ok(Attachment { parent, point, pin }))
    }

    /// Check the operands of a pivot and find what it moves.
    fn pivot(
        &self,
        process: &BrokerProcess,
        user: FileUser,
        new_root: MountPath<'_>,
        put_old: MountPath<'_>,
    ) -> Result<FileResult<Pivot>> {
        let new = match self.find(process, user, new_root, false)? {
            Ok(found) => found,
            Err(error) => return Ok(Err(error)),
        };
        let old = match self.find(process, user, put_old, false)? {
            Ok(found) => found,
            Err(error) => return Ok(Err(error)),
        };
        if new.kind != Kind::Dir || old.kind != Kind::Dir {
            return Ok(Err(FileError::NotDirectory));
        }
        let root = &self.snapshot.root;
        let (old_root, new_root) = (&root.mount, &new.location.mount);
        let tree = self.namespace.tree();
        let in_namespace = [old_root, new_root, &old.location.mount]
            .into_iter()
            .all(|mount| tree.contains(mount));
        if !in_namespace {
            return Ok(Err(FileError::InvalidArgument));
        }
        // In Linux's order: neither the new root nor the mount on top at `put_old` may be the
        // caller's root mount, before the other checks.
        let (old_parent, old_point) = tree.top(&old.location.mount, &old.location.path);
        if Arc::ptr_eq(old_root, new_root) || Arc::ptr_eq(old_root, &old_parent) {
            return Ok(Err(FileError::Busy));
        }
        let new_root_location = Location::root_of(Arc::clone(new_root));
        if !root.path.is_empty()
            || !new.location.path.is_empty()
            || tree.parent(new_root).is_none()
            || tree.path_from(root, &new_root_location).is_none()
            || tree.path_from(&new_root_location, &old.location).is_none()
        {
            return Ok(Err(FileError::InvalidArgument));
        }
        let old_pin = match old_parent.pin(&old_point) {
            Ok(pin) => pin,
            Err(error) => return Ok(Err(error)),
        };
        if let Err(error) = expect_point(&old_parent, &old_point, Kind::Dir) {
            return Ok(Err(error));
        }
        let old_root_place = tree
            .parent(old_root)
            .map(|(parent, point)| (Arc::clone(parent), point.to_vec()));
        Ok(Ok(Pivot {
            old_root: Arc::clone(old_root),
            old_root_place,
            new_root: Arc::clone(new_root),
            old_parent,
            old_point,
            old_pin,
        }))
    }
}

/// Check that `point`, a point inside `parent` that a mount is to be attached at, pinned, exists as
/// a node of kind `kind`. Pinned, it can't be removed or renamed any more; this checks it wasn't
/// before: its path inside the backend, which the pin names, as a handle the caller resolved it
/// through can name a removed directory; and, at the root of `parent`, the root itself, as a file
/// bind's root must still be the node bound.
fn expect_point(parent: &Arc<Mount>, point: &[String], kind: Kind) -> FileResult<()> {
    let at_path = parent.resolve_backend_path(point, |resolution| Kind::of(&resolution));
    let at_root = if point.is_empty() {
        resolve_location(&Location::root_of(Arc::clone(parent)), |resolution| {
            Kind::of(&resolution)
        })
    } else {
        Ok(Some(kind))
    };
    match (at_path, at_root) {
        (Ok(Some(at_path)), Ok(Some(at_root))) if at_path == kind && at_root == kind => Ok(()),
        _ => Err(FileError::NoSuchFileOrDirectory),
    }
}

/// Where a mount attaches: the top of the stack at a point, pinned.
struct Attachment {
    parent: Arc<Mount>,
    point: Vec<String>,
    pin: Pin,
}

/// A copy of a mount to attach, with what it attaches to.
struct Below {
    parent: Arc<Mount>,
    point: Vec<String>,
    mount: Arc<Mount>,
    pin: Pin,
}

impl Attachment {
    /// Attach `mount` here, and the copies `below` under it.
    fn commit(
        self,
        change: &mut super::mount::TreeChange,
        mount: Arc<Mount>,
        below: Vec<Below>,
    ) -> FileResult<()> {
        if !change.tree().contains(&self.parent) {
            return Err(FileError::InvalidArgument);
        }
        change.attach(self.parent, self.point, mount, self.pin);
        for below in below {
            change.attach(below.parent, below.point, below.mount, below.pin);
        }
        Ok(())
    }
}

/// A checked pivot: the mounts it moves, and where.
struct Pivot {
    old_root: Arc<Mount>,
    /// Where the old root mount is attached, if it isn't the namespace's root.
    old_root_place: Option<(Arc<Mount>, Vec<String>)>,
    new_root: Arc<Mount>,
    /// Where the old root mount goes, pinned.
    old_parent: Arc<Mount>,
    old_point: Vec<String>,
    old_pin: Pin,
}

impl Pivot {
    /// Move the mounts, then every root and working directory at the old root, returning what
    /// those replace and the contexts, for the caller to drop outside the namespace's lock.
    fn commit(
        self,
        change: &mut super::mount::TreeChange,
        core: &crate::BrokerCore,
    ) -> (Vec<super::mount::HeldLocation>, Vec<Arc<FsContext>>) {
        // The new root mount takes the old one's point, so it takes its pin too.
        let place_pin = self.old_root.take_pin();
        change.move_mount(
            &self.old_root,
            Some((self.old_parent, self.old_point)),
            Some(self.old_pin),
        );
        change.move_mount(&self.new_root, self.old_root_place, place_pin);
        let from = Location::root_of(self.old_root);
        let to = Location::root_of(self.new_root);
        // Like Linux's `chroot_fs_refs`, every context, in any namespace, as one can hold a root
        // or working directory on a mount of another. The registry stays locked throughout, as
        // contexts are copied and registered under its lock, so none misses the move.
        let registry = core.fs_contexts.lock();
        let contexts: Vec<_> = registry
            .iter()
            .filter_map(alloc::sync::Weak::upgrade)
            .collect();
        let replaced = contexts
            .iter()
            .flat_map(|context| context.move_from(&from, &to))
            .collect();
        drop(registry);
        (replaced, contexts)
    }
}

/// A new mount of the node `found` names, charged as `quota`: a bind of it.
fn bind_mount(
    namespace: &MountNamespace,
    found: &Found,
    quota: QuotaReservation,
) -> FileResult<Arc<Mount>> {
    let source = &found.location;
    let backend = source.mount.backend();
    let root = if source.path.is_empty() {
        source.mount.root().clone()
    } else if found.kind == Kind::Dir {
        let dir = resolve_location(source, |resolution| match resolution {
            Resolution::Found(ResolvedTarget::Dir(dir)) => backend
                .open_dir(dir, OFlags::PATH)
                .map_err(|_| FileError::NoSuchFileOrDirectory),
            _ => Err(FileError::NoSuchFileOrDirectory),
        })
        .map_err(file_walk_error)??;
        MountRoot::Dir(dir)
    } else {
        // A file is found through its directory.
        let (name, parent_path) = source
            .path
            .split_last()
            .expect("a path that isn't a mount's root has a name");
        let mut parent = source.clone();
        parent.path = parent_path.to_vec();
        if parent.anchor_depth > parent.path.len() {
            parent.anchor = None;
            parent.anchor_depth = parent.path.len();
        }
        let dir = resolve_location(&parent, |resolution| match resolution {
            Resolution::Found(ResolvedTarget::Dir(dir)) => backend
                .open_dir(dir, OFlags::PATH)
                .map_err(|_| FileError::NoSuchFileOrDirectory),
            _ => Err(FileError::NoSuchFileOrDirectory),
        })
        .map_err(file_walk_error)??;
        MountRoot::file(&**backend, dir, name.clone()).map_err(file_walk_error)?
    };
    let mount = namespace.new_mount(
        Arc::clone(backend),
        root,
        source.mount.backend_path(&source.path),
        source.mount.info().clone(),
        Some(quota),
    );
    // Like Linux's, a bind starts with its source mount's read-only flag.
    mount
        .set_read_only(source.mount.is_read_only())
        .map_err(|_| FileError::Busy)?;
    Ok(mount)
}

/// Copies of the mounts of `tree` attached at or below `source`, each attached to a copy of what
/// it is attached to, or to `mount` (a bind of `source`) at the same point relative to `source`,
/// pinned and charged to `process`; each after what it is attached to.
fn copy_below(
    process: &BrokerProcess,
    namespace: &MountNamespace,
    tree: &MountTree,
    source: &Location,
    mount: &Arc<Mount>,
) -> Result<FileResult<Vec<Below>>> {
    let mut below = Vec::new();
    let mut originals = Vec::new();
    for (point, child) in tree.children(&source.mount) {
        let Some(point) = point.strip_prefix(source.path.as_slice()) else {
            continue;
        };
        let copy = namespace.copy_mount(child, Some(process.charge_mount()?));
        let pin = match mount.pin(point) {
            Ok(pin) => pin,
            Err(error) => return Ok(Err(error)),
        };
        below.push(Below {
            pin,
            parent: Arc::clone(mount),
            point: point.to_vec(),
            mount: Arc::clone(&copy),
        });
        originals.push((Arc::clone(child), copy));
    }
    while let Some((original, copy)) = originals.pop() {
        for (point, child) in tree.children(&original) {
            let child_copy = namespace.copy_mount(child, Some(process.charge_mount()?));
            let pin = match copy.pin(point) {
                Ok(pin) => pin,
                Err(error) => return Ok(Err(error)),
            };
            below.push(Below {
                pin,
                parent: Arc::clone(&copy),
                point: point.to_vec(),
                mount: Arc::clone(&child_copy),
            });
            originals.push((Arc::clone(child), child_copy));
        }
    }
    Ok(Ok(below))
}

/// A new, empty in-memory backend for `namespace`, whose root directory has `mode` and `owner`.
fn tmpfs(
    namespace: &MountNamespace,
    mode: FileMode,
    owner: FileUser,
) -> FileResult<Arc<dyn Backend>> {
    let backend = namespace.ops().new_tmpfs(namespace.allocators().next());
    let root = || {
        backend
            .root()
            .map(ResolvedTarget::Dir)
            .map_err(file_walk_error)
    };
    backend
        .chmod(root()?, mode & FileMode::SUPPORTED)
        .map_err(|_| FileError::Io)?;
    backend
        .chown(root()?, Some(owner.user), Some(owner.group))
        .map_err(|_| FileError::Io)?;
    Ok(backend)
}

#[cfg(test)]
mod tests;
