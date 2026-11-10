// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Path management, permission checks, and open-state operations above [`super::backend`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;

use litebox_broker_protocol::fs::FileLockOperation;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::RawSyncPrimitivesProvider;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SeekError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::mount::{Location, Mount, MountNamespace, MountTree, absolute_path, allow_lookup};
use super::{
    FileTimeUpdate, FileType, Mode, OFlags, SetFileTimes,
    backend::{
        Backend, CreationMetadata, DirHandle, FileTerminal, Handle, HandleRef, PermissionCheck,
        PermissionInfo, Resolution, ResolvedDir, ResolvedTarget, SeekBehavior,
    },
};
use super::{SeekWhence, UserInfo};
use crate::readiness::ReadinessSource;
use crate::terminal::TerminalEndpoint;

/// Maximum number of symbolic links followed while resolving a single path; following more fails
/// with [`PathError::TooManySymlinks`].
const MAX_SYMLINKS: usize = 40;

/// The broker-core filesystem resolver, generic over its synchronization platform.
///
/// It resolves paths in a tree of mounts, each showing a [`Backend`], and starts with one mount,
/// at the root, showing the backend it was constructed over.
pub struct Resolver<Platform: RawSyncPrimitivesProvider> {
    namespace: Arc<MountNamespace>,
    flocks: super::flock::FlockTable<Platform>,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Platform: RawSyncPrimitivesProvider> Resolver<Platform> {
    /// Construct a filesystem resolver over `backend`.
    #[must_use]
    pub fn new(backend: impl Backend) -> Self {
        Self {
            namespace: MountNamespace::new(Arc::new(backend)),
            flocks: super::flock::FlockTable::new(),
            _sync: PhantomData,
        }
    }

    /// The namespace whose mounts this resolver resolves paths in.
    #[cfg(test)]
    pub(crate) fn namespace(&self) -> &Arc<MountNamespace> {
        &self.namespace
    }

    /// The root that paths resolve from.
    fn root(&self) -> Location {
        self.namespace.root()
    }
}

struct Context {
    user_info: UserInfo,
}

impl Context {
    fn new(user_info: UserInfo) -> Self {
        Self { user_info }
    }

    fn acting_user(&self) -> UserInfo {
        self.user_info
    }

    fn can_execute(&self, permissions: &PermissionInfo) -> bool {
        if self.user_info.user == permissions.owner.user {
            permissions.mode.contains(Mode::XUSR)
        } else if self.user_info.group == permissions.owner.group {
            permissions.mode.contains(Mode::XGRP)
        } else {
            permissions.mode.contains(Mode::XOTH)
        }
    }

    fn can_read(&self, permissions: &PermissionInfo) -> bool {
        if self.user_info.user == permissions.owner.user {
            permissions.mode.contains(Mode::RUSR)
        } else if self.user_info.group == permissions.owner.group {
            permissions.mode.contains(Mode::RGRP)
        } else {
            permissions.mode.contains(Mode::ROTH)
        }
    }

    fn can_write(&self, permissions: &PermissionInfo) -> bool {
        if self.user_info.user == permissions.owner.user {
            permissions.mode.contains(Mode::WUSR)
        } else if self.user_info.group == permissions.owner.group {
            permissions.mode.contains(Mode::WGRP)
        } else {
            permissions.mode.contains(Mode::WOTH)
        }
    }

    fn check_search_permission(&self, permissions: &PermissionInfo) -> Result<(), WalkError> {
        if !self.can_execute(permissions) {
            litebox_util_log::debug!(perms:? = permissions.mode; "no search permission");
            return Err(PathError::NoSearchPerms.into());
        }
        Ok(())
    }

    /// Check that the caller may add or remove entries in `dir`: `read_only` if `dir` is on a
    /// read-only filesystem, whatever its mode (Linux checks the mount before permissions), else
    /// `no_write_perms` if the caller can't write `dir`.
    fn check_dir_entries_change<E>(
        &self,
        dir: &ResolvedDir<'_>,
        read_only: E,
        no_write_perms: E,
    ) -> Result<(), E> {
        match &dir.permissions {
            PermissionCheck::ByResolver(permissions) if permissions.on_read_only_fs => {
                Err(read_only)
            }
            PermissionCheck::ByResolver(permissions) if !self.can_write(permissions) => {
                Err(no_write_perms)
            }
            PermissionCheck::ByBackend | PermissionCheck::ByResolver(_) => Ok(()),
        }
    }

    fn may_change_metadata(&self, target: &ResolvedTarget<'_>) -> bool {
        let permissions = match target {
            ResolvedTarget::Dir(dir) => &dir.permissions,
            ResolvedTarget::File(file) => &file.permissions,
        };
        let PermissionCheck::ByResolver(permissions) = permissions else {
            return true;
        };
        let acting = self.acting_user();
        acting.user == UserInfo::ROOT.user || acting.user == permissions.owner.user
    }
}

/// Resolve `path` for `user` from `base` (or from `root` if `path` is absolute), never climbing
/// above `root`, and pass the location reached and its resolution to `found`. See [`walk`].
#[cfg_attr(not(test), expect(dead_code, reason = "mount operations use it"))]
pub(crate) fn resolve_from<R>(
    user: UserInfo,
    root: &Location,
    base: &Location,
    path: &str,
    follow_final: bool,
    found: impl for<'m> FnOnce(&'m Location, Resolution<'m>) -> R,
) -> Result<R, WalkError> {
    walk(
        &Context::new(user),
        root,
        base,
        path,
        follow_final,
        false,
        found,
    )
}

/// A walk's position.
struct Walk {
    /// A snapshot of the tree of the location's mount, taken when the walk entered the tree.
    tree: Arc<MountTree>,
    location: Location,
    /// Depths along `location.path` of directories the caller was found allowed to search.
    searchable: Range<usize>,
}

impl Walk {
    fn at(location: &Location) -> Self {
        Self {
            tree: location.mount.tree(),
            location: location.clone(),
            searchable: 0..0,
        }
    }

    /// How many of the plain names at the front of `pending` can be walked inside the current
    /// mount before one reaches a point with a mount attached.
    fn run_length(&self, pending: &VecDeque<String>) -> usize {
        let plain = pending
            .iter()
            .take_while(|name| !matches!(name.as_str(), "." | ".."))
            .count();
        let path = self.location.path.as_slice();
        self.tree
            .points(&self.location.mount)
            .filter_map(|point| {
                let below = point.strip_prefix(path)?;
                (!below.is_empty()
                    && below.len() <= plain
                    && below.iter().zip(pending).all(|(point, name)| point == name))
                .then(|| below.len() - 1)
            })
            .fold(plain, usize::min)
    }

    /// Step up to the parent directory inside the current mount, if there is one. The location
    /// keeps its anchor only while it stays at or below it.
    fn pop(&mut self) -> bool {
        if self.location.path.pop().is_none() {
            return false;
        }
        let depth = self.location.path.len();
        if self.location.anchor_depth > depth {
            self.location.anchor = None;
            self.location.anchor_depth = depth;
        }
        self.searchable.end = self.searchable.end.min(depth + 1);
        true
    }

    /// Follow `..`: stay at `root`; else step up inside the mount; else, at a mount's root, climb
    /// to its point in its parent mount and try again, or stay if it has none (a namespace's root
    /// mount, or a detached one). Then follow the mounts attached where it ends, as Linux's
    /// `handle_dots` does.
    fn dot_dot(&mut self, root: &Location) {
        while !self.location.is_at(root) && !self.pop() {
            let Some((parent, point)) = self.tree.parent(&self.location.mount) else {
                break;
            };
            self.location = Location::unanchored(Arc::clone(parent), point.to_vec());
            self.searchable = 0..0;
        }
        self.follow_mounts();
    }

    /// Move to the root of the mount attached at the location, repeatedly while there is one, as
    /// Linux's `traverse_mounts` does.
    fn follow_mounts(&mut self) {
        while let Some(child) = self.tree.child(&self.location.mount, &self.location.path) {
            self.location = Location::root_of(Arc::clone(child));
            self.searchable = 0..0;
        }
    }
}

/// Resolve `components`, a path inside `mount`, from the anchor at `anchor_depth` (see
/// [`Location`]), checking search permission from it down. Error component indexes are positions
/// in `components`.
fn resolve_in<'m>(
    context: &Context,
    mount: &'m Mount,
    anchor: Option<&DirHandle>,
    anchor_depth: usize,
    components: &[&str],
) -> Result<Resolution<'m>, ResolutionError> {
    resolve_from_anchor(context, mount, anchor, anchor_depth, components).map_err(|mut error| {
        if let Some(index) = error.component
            && let WalkError::PathError(PathError::NoSearchPerms) = &error.error
        {
            litebox_util_log::debug!(
                dir:% = alloc::format!("/{}", components[..index.min(components.len())].join("/"));
                "no search permission"
            );
        }
        // A missing mount root reports `NoSuchFileOrDirectory` when it is the target.
        if matches!(
            error.error,
            WalkError::PathError(PathError::NoSuchFileOrDirectory)
        ) && !components.is_empty()
            && error
                .component
                .is_none_or(|index| index < components.len() - 1)
        {
            // TODO(jayb): keeps ENOENT for a final name hidden by Composer (see composer
            // shadowed-file handling).
            error.error = PathError::MissingComponent.into();
        }
        error
    })
}

fn resolve_from_anchor<'m>(
    context: &Context,
    mount: &'m Mount,
    anchor: Option<&DirHandle>,
    anchor_depth: usize,
    components: &[&str],
) -> Result<Resolution<'m>, ResolutionError> {
    let at = |component| move |error| ResolutionError { component, error };
    let backend = mount.backend();
    // A walk to a node above the anchor trusts all of its path.
    let depth = anchor_depth.min(components.len());
    let anchor = anchor
        .filter(|_| depth == anchor_depth)
        .and_then(|anchor| backend.walking_dir_at(anchor));
    let start = if let Some(anchor) = anchor {
        anchor
    } else {
        let root = match mount.resolve_root().map_err(at(None))? {
            ResolvedTarget::Dir(root) => root,
            file if components.is_empty() => return Ok(Resolution::Found(file)),
            ResolvedTarget::File(_) => {
                return Err(at(Some(0))(PathError::ComponentNotADirectory.into()));
            }
        };
        let resolution = backend.resolve(root, &components[..depth], &allow_lookup)?;
        if depth == components.len() {
            return Ok(resolution);
        }
        match resolution {
            Resolution::Found(ResolvedTarget::Dir(dir)) => dir,
            Resolution::Found(ResolvedTarget::File(_)) => {
                return Err(at(Some(depth))(PathError::ComponentNotADirectory.into()));
            }
            Resolution::MissingFinal { .. } => {
                return Err(at(depth.checked_sub(1))(
                    PathError::NoSuchFileOrDirectory.into(),
                ));
            }
        }
    };
    backend
        .resolve(start, &components[depth..], &|permissions| {
            context.check_search_permission(permissions)
        })
        .map_err(|mut error| {
            error.component = error.component.map(|index| index + depth);
            error
        })
}

/// Check that the caller may search the directory at `walk`'s location before stepping from it
/// without looking anything up in it (`.`, `..`, or onto a mount point), as Linux's `may_lookup`
/// checks every directory a component is looked up in.
fn ensure_searchable(context: &Context, walk: &mut Walk) -> Result<(), WalkError> {
    let depth = walk.location.path.len();
    if walk.searchable.contains(&depth) {
        return Ok(());
    }
    let components: Vec<&str> = walk.location.path.iter().map(String::as_str).collect();
    match resolve_in(
        context,
        &walk.location.mount,
        walk.location.anchor.as_ref(),
        walk.location.anchor_depth,
        &components,
    )
    .map_err(|error| error.error)?
    {
        Resolution::Found(ResolvedTarget::Dir(dir)) => {
            if let PermissionCheck::ByResolver(permissions) = &dir.permissions {
                context.check_search_permission(permissions)?;
            }
        }
        Resolution::Found(ResolvedTarget::File(_)) => {
            return Err(PathError::ComponentNotADirectory.into());
        }
        Resolution::MissingFinal { .. } => return Err(PathError::NoSuchFileOrDirectory.into()),
    }
    walk.searchable = walk.location.anchor_depth..depth + 1;
    Ok(())
}

/// Read the target of the symbolic link at `location`.
fn read_link_target(context: &Context, location: &Location) -> Result<String, WalkError> {
    // A mount's root is never a symbolic link.
    let Some((name, parent)) = location.path.split_last() else {
        return Err(PathError::InvalidPathname.into());
    };
    let components: Vec<&str> = parent.iter().map(String::as_str).collect();
    // TODO(jayb): add a resolved-file read_link to avoid re-resolving the parent.
    let Resolution::Found(ResolvedTarget::Dir(parent)) = resolve_in(
        context,
        &location.mount,
        location.anchor.as_ref(),
        location.anchor_depth,
        &components,
    )
    .map_err(|error| error.error)?
    else {
        return Err(PathError::MissingComponent.into());
    };
    location.mount.backend().read_link_at(&parent, name)
}

/// Resolve `path` for `context` from `base` (or from `root` if `path` is absolute), never climbing
/// above `root`, and pass the location reached and its resolution to `found`, as the resolution
/// borrows the location's mount.
///
/// Like Linux, a walk doesn't follow the mounts stacked on where it starts; it follows those it
/// steps onto, and those where `..` ends. It looks names up in runs inside one mount at a time,
/// from the anchor of its location, and checks search permission on every directory it looks a
/// name up in or steps from. Absolute symbolic links restart it at `root`.
// XXX(jayb): each run re-resolves from the anchor, since `Backend::resolve` consumes its starting
// directory and does not report symlinks mid-walk.
// XXX: broker paths are absolute. The client (`litebox::fs::Context::resolve`) also normalizes
// paths lexically before sending them: it collapses `.`/`..` (so `link/..` names the link's parent
// rather than, as on Linux, its target's parent) and drops trailing slashes, so `require_directory`
// and the final `.`/`..` checks below never trigger for guest paths (e.g. `unlink("link/")` removes
// the link).
fn walk<R>(
    context: &Context,
    root: &Location,
    base: &Location,
    path: &str,
    follow_final: bool,
    allow_missing: bool,
    found: impl for<'m> FnOnce(&'m Location, Resolution<'m>) -> R,
) -> Result<R, WalkError> {
    let mut pending: VecDeque<String> = path
        .split('/')
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect();
    let mut require_directory = path.ends_with('/');
    let mut walk = Walk::at(if path.starts_with('/') { root } else { base });
    let mut links = 0;
    loop {
        match pending.front().map(String::as_str) {
            Some(".") => {
                ensure_searchable(context, &mut walk)?;
                pending.pop_front();
                continue;
            }
            Some("..") => {
                ensure_searchable(context, &mut walk)?;
                pending.pop_front();
                walk.dot_dot(root);
                continue;
            }
            _ => {}
        }
        let run_len = walk.run_length(&pending);
        if run_len == 0 && !pending.is_empty() {
            // The next name has a mount attached: step onto it, into the mounts stacked there.
            ensure_searchable(context, &mut walk)?;
            walk.location.path.extend(pending.pop_front());
            walk.follow_mounts();
            continue;
        }
        // Resolve the run, or, with no names left, the location itself.
        let run_start = walk.location.path.len();
        walk.location.path.extend(pending.drain(..run_len));
        // The resolution borrows the mount, so it must end before the walk moves.
        let target = {
            let mut end = walk.location.path.len();
            let resolution = loop {
                let components: Vec<_> = walk.location.path[..end]
                    .iter()
                    .map(String::as_str)
                    .collect();
                match resolve_in(
                    context,
                    &walk.location.mount,
                    walk.location.anchor.as_ref(),
                    walk.location.anchor_depth,
                    &components,
                ) {
                    // Retry from the failing child's parent so a mid-run symlink gets followed.
                    Err(ResolutionError {
                        component,
                        error: WalkError::PathError(PathError::ComponentNotADirectory),
                    }) if end > run_start + 1 => {
                        end = component
                            .filter(|&index| run_start < index && index < end)
                            .unwrap_or(end - 1);
                    }
                    result => break result.map_err(|error| error.error)?,
                }
            };
            for part in walk.location.path.drain(end..).rev() {
                pending.push_front(part);
            }
            // The walk authorized looking a name up in each directory from the anchor down.
            walk.searchable = walk.location.anchor_depth..end;
            let final_component = pending.is_empty();
            match resolution {
                Resolution::Found(ResolvedTarget::Dir(dir)) => {
                    if final_component {
                        return Ok(found(
                            &walk.location,
                            Resolution::Found(ResolvedTarget::Dir(dir)),
                        ));
                    }
                    // `sub/../f` must still require search permission on `sub`.
                    if let PermissionCheck::ByResolver(permissions) = &dir.permissions {
                        context.check_search_permission(permissions)?;
                    }
                    walk.searchable.end = end + 1;
                    continue;
                }
                Resolution::Found(ResolvedTarget::File(file))
                    if file.file_type == FileType::SymbolicLink =>
                {
                    if final_component && !follow_final && !require_directory {
                        return Ok(found(
                            &walk.location,
                            Resolution::Found(ResolvedTarget::File(file)),
                        ));
                    }
                    drop(file);
                    links += 1;
                    if links > MAX_SYMLINKS {
                        return Err(PathError::TooManySymlinks.into());
                    }
                    let target = read_link_target(context, &walk.location)?;
                    if final_component && target.ends_with('/') {
                        require_directory = true;
                    }
                    target
                }
                Resolution::Found(ResolvedTarget::File(file)) => {
                    if !final_component || require_directory {
                        return Err(PathError::ComponentNotADirectory.into());
                    }
                    return Ok(found(
                        &walk.location,
                        Resolution::Found(ResolvedTarget::File(file)),
                    ));
                }
                Resolution::MissingFinal { parent } => {
                    if final_component && allow_missing && !require_directory {
                        return Ok(found(&walk.location, Resolution::MissingFinal { parent }));
                    }
                    return Err(if final_component {
                        PathError::NoSuchFileOrDirectory
                    } else {
                        PathError::MissingComponent
                    }
                    .into());
                }
            }
        };
        if target.starts_with('/') {
            walk = Walk::at(root);
        } else {
            // Continue from the link's directory. `read_link_target` failed at a mount's root,
            // which has none.
            walk.pop();
        }
        for part in target.split('/').filter(|part| !part.is_empty()).rev() {
            pending.push_front(String::from(part));
        }
    }
}

/// The path of `location` from `root`, or its path inside its mount if `root` is not above it.
fn path_from(root: &Location, location: &Location) -> String {
    location
        .mount
        .tree()
        .path_from(root, location)
        .unwrap_or_else(|| absolute_path(&location.path))
}

/// Resolve the directory that `path`'s final name is in, check that the caller may search it, and
/// pass its mount, its resolution and the name to `f`. `None` if `path` names the root.
///
/// Entry mutations resolve the parent but keep the final name, so neither a link nor a final
/// `.`/`..` can redirect a removal to an ordinary target directory. The resolution stays alive
/// across `f`, so backend locks stay held.
fn with_parent<R>(
    context: &Context,
    root: &Location,
    path: &str,
    f: impl for<'m> FnOnce(&'m Arc<Mount>, ResolvedDir<'m>, &str) -> R,
) -> Result<Option<R>, WalkError> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(None);
    }
    let (parent_path, name) = match trimmed.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some(parts) => parts,
        None => ("", trimmed),
    };
    walk(
        context,
        root,
        root,
        parent_path,
        true,
        false,
        |location, resolution| {
            let parent = match resolution {
                Resolution::Found(ResolvedTarget::Dir(parent)) => parent,
                Resolution::Found(ResolvedTarget::File(_)) => {
                    return Err(PathError::ComponentNotADirectory.into());
                }
                Resolution::MissingFinal { .. } => return Err(PathError::MissingComponent.into()),
            };
            if let PermissionCheck::ByResolver(permissions) = &parent.permissions {
                context.check_search_permission(permissions)?;
            }
            Ok(Some(f(&location.mount, parent, name)))
        },
    )?
}

fn authorize_set_times(
    context: &Context,
    target: &ResolvedTarget<'_>,
    times: &SetFileTimes,
) -> Result<(), SetTimesError> {
    if matches!(
        (times.access, times.modify),
        (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
    ) {
        return Ok(());
    }
    let permissions = match target {
        ResolvedTarget::Dir(dir) => &dir.permissions,
        ResolvedTarget::File(file) => &file.permissions,
    };
    let PermissionCheck::ByResolver(permissions) = permissions else {
        return Ok(());
    };
    if permissions.on_read_only_fs {
        return Err(SetTimesError::ReadOnlyFileSystem);
    }
    if context.may_change_metadata(target) {
        return Ok(());
    }
    // Only both-NOW lets write access substitute for ownership.
    if matches!(
        (times.access, times.modify),
        (FileTimeUpdate::Now, FileTimeUpdate::Now)
    ) {
        return if context.can_write(permissions) {
            Ok(())
        } else {
            Err(SetTimesError::AccessNotAllowed)
        };
    }
    Err(SetTimesError::NotTheOwner)
}

fn name_exists<'a>(
    context: &Context,
    mount: &'a Mount,
    parent: ResolvedDir<'a>,
    name: &str,
) -> Result<bool, WalkError> {
    let resolution = mount
        .backend()
        .resolve(parent, &[name], &|permissions| {
            context.check_search_permission(permissions)
        })
        .map_err(|error| error.error)?;
    Ok(matches!(resolution, Resolution::Found(_)))
}

impl<Platform: RawSyncPrimitivesProvider> Resolver<Platform> {
    /// Resolve an absolute path to its physical location, following symbolic links.
    pub fn resolve_following_symlinks(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<String, WalkError> {
        let root = self.root();
        walk(
            &Context::new(user),
            &root,
            &root,
            path,
            true,
            false,
            |location, _| path_from(&root, location),
        )
    }

    /// Read a symbolic link's stored target, without following the final link.
    pub fn read_link(&self, user: UserInfo, path: &str) -> Result<String, WalkError> {
        let context = Context::new(user);
        let root = self.root();
        walk(
            &context,
            &root,
            &root,
            path,
            false,
            false,
            |location, resolution| {
                let is_link = matches!(
                    &resolution,
                    Resolution::Found(ResolvedTarget::File(file))
                        if file.file_type == FileType::SymbolicLink
                );
                drop(resolution);
                if !is_link {
                    return Err(PathError::InvalidPathname.into());
                }
                read_link_target(&context, location)
            },
        )?
    }
}

impl<Platform: RawSyncPrimitivesProvider> Resolver<Platform> {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file. Opening a file
    /// that refers to the opener's controlling terminal for I/O fails with
    /// [`OpenError::NoSuchDevice`], as if the opener had none (see
    /// [`open_with_controlling_terminal`](Self::open_with_controlling_terminal)).
    pub fn open(
        &self,
        user: UserInfo,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<ResolverEntry, OpenError> {
        self.open_with_controlling_terminal(user, path, flags, mode, &|| None)
    }

    /// Opens a file like [`open`](Self::open), binding a file that refers to
    /// the opener's controlling terminal to `controlling_terminal()`, which it
    /// holds open (see [`TerminalEndpoint::reopen`]) and through which its I/O
    /// then goes.
    ///
    /// Like Linux, opening such a file for I/O fails with
    /// [`OpenError::NoSuchDevice`] if the opener has no controlling terminal,
    /// while opening it only for path-based operations does not.
    pub fn open_with_controlling_terminal(
        &self,
        user: UserInfo,
        path: &str,
        flags: OFlags,
        mode: Mode,
        controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
    ) -> Result<ResolverEntry, OpenError> {
        let mut entry = self.open_entry(user, path, flags, mode)?;
        if let Handle::File(file) = &entry.handle
            && !entry.path_only
            && matches!(
                entry.mount.backend().terminal(file),
                Some(FileTerminal::OpenersControlling)
            )
        {
            let terminal = controlling_terminal().ok_or(OpenError::NoSuchDevice)?;
            entry.controlling_terminal = Some(ReopenedTerminal {
                _file: Arc::clone(&terminal).reopen()?,
                terminal,
            });
        }
        Ok(entry)
    }

    fn open_entry(
        &self,
        user: UserInfo,
        path: &str,
        mut flags: OFlags,
        mode: Mode,
    ) -> Result<ResolverEntry, OpenError> {
        const CURRENTLY_SUPPORTED_OFLAGS: OFlags = OFlags::CREAT
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

        if flags.intersects(CURRENTLY_SUPPORTED_OFLAGS.complement()) {
            unimplemented!("{flags:?}")
        }
        let path_only = flags.contains(OFlags::PATH);
        if path_only {
            // For `PATH`, we restrict what other flags are allowed, so a missing path cannot lead
            // to a creation, etc.
            flags &= OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        }

        let context = Context::new(user);
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let root = self.root();
        walk(
            &context,
            &root,
            &root,
            path,
            !flags.contains(OFlags::NOFOLLOW) && !flags.contains(OFlags::CREAT | OFlags::EXCL),
            flags.contains(OFlags::CREAT),
            |location, resolution| {
                let backend = location.mount.backend();
                let entry = |handle, seek_behavior| ResolverEntry {
                    handle,
                    mount: Arc::clone(&location.mount),
                    read_allowed,
                    write_allowed,
                    position: 0,
                    append_mode,
                    nonblocking,
                    path_only,
                    seek_behavior,
                    path: path_from(&root, location),
                    controlling_terminal: None,
                };
                match resolution {
                    Resolution::Found(_) if flags.contains(OFlags::CREAT | OFlags::EXCL) => {
                        Err(OpenError::AlreadyExists)
                    }
                    Resolution::Found(ResolvedTarget::Dir(dir)) => {
                        // XXX(jayb): non-read, non-PATH dir opens check search instead of read
                        // (#884/#888 workaround); Linux returns EISDIR for write opens.
                        if !path_only
                            && let PermissionCheck::ByResolver(permissions) = &dir.permissions
                            && if read_allowed {
                                !context.can_read(permissions)
                            } else {
                                !context.can_execute(permissions)
                            }
                        {
                            return Err(OpenError::AccessNotAllowed);
                        }
                        Ok(entry(
                            Handle::Dir(backend.open_dir(dir, flags)?),
                            SeekBehavior::NonSeekable,
                        ))
                    }
                    Resolution::Found(ResolvedTarget::File(file)) => {
                        if file.file_type == FileType::SymbolicLink
                            && !flags.contains(OFlags::PATH | OFlags::NOFOLLOW)
                        {
                            return Err(if flags.contains(OFlags::DIRECTORY) {
                                PathError::ComponentNotADirectory
                            } else {
                                PathError::TooManySymlinks
                            }
                            .into());
                        }
                        // O_TRUNC needs write permission even with O_RDONLY.
                        if flags.contains(OFlags::DIRECTORY) {
                            return Err(PathError::ComponentNotADirectory.into());
                        }
                        let wants_write = write_allowed || flags.contains(OFlags::TRUNC);
                        if !path_only
                            && let PermissionCheck::ByResolver(permissions) = &file.permissions
                        {
                            if wants_write && permissions.on_read_only_fs {
                                return Err(OpenError::ReadOnlyFileSystem);
                            }
                            if (read_allowed && !context.can_read(permissions))
                                || (wants_write && !context.can_write(permissions))
                            {
                                return Err(OpenError::AccessNotAllowed);
                            }
                        }
                        let file = backend.open_file(file, flags)?;
                        let seek_behavior = backend.seek_behavior(&file);
                        Ok(entry(Handle::File(file), seek_behavior))
                    }
                    Resolution::MissingFinal { parent } if flags.contains(OFlags::CREAT) => {
                        let Some(name) = location.path.last() else {
                            // Only a name looked up in a directory can be missing.
                            unreachable!()
                        };
                        context.check_dir_entries_change(
                            &parent,
                            OpenError::ReadOnlyFileSystem,
                            OpenError::NoWritePerms,
                        )?;
                        let file = backend.create_file_at(
                            parent,
                            name,
                            CreationMetadata {
                                mode,
                                owner: context.acting_user(),
                            },
                        )?;
                        let seek_behavior = backend.seek_behavior(&file);
                        Ok(entry(Handle::File(file), seek_behavior))
                    }
                    Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
                }
            },
        )
        .map_err(|error| match error {
            WalkError::Io => OpenError::Io,
            WalkError::PathError(error) => error.into(),
        })?
    }

    pub(crate) fn read_without_position_update(
        entry: &ResolverEntry,
        buf: &mut dyn ReadBuffer,
        offset: Option<usize>,
    ) -> Result<(usize, usize), ReadError> {
        if entry.path_only {
            return Err(ReadError::NotForReading);
        }
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(ReadError::NotAFile),
        };
        let seek_behavior = entry.seek_behavior;
        if !entry.read_allowed {
            return Err(ReadError::NotForReading);
        }
        if let Some(controlling) = &entry.controlling_terminal {
            return Ok((controlling.terminal.read(buf)?, 0));
        }

        let read_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased => offset.unwrap_or(entry.position),
        };
        let read = entry.mount.backend().read(file, buf, read_offset)?;
        Ok((read, read_offset))
    }

    /// Read from a file descriptor at `offset` into a buffer
    ///
    /// If `offset` is None, the read will start at the current file offset and update the file
    /// offset to the end of the read.
    /// If `offset` is Some, the file offset is not changed.
    ///
    /// # Panics
    ///
    /// Panics if the updated file offset would overflow `usize`.
    pub fn read(
        &self,
        entry: &mut ResolverEntry,
        buf: &mut dyn ReadBuffer,
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let (read, read_offset) = Self::read_without_position_update(entry, buf, offset)?;
        if entry.uses_position() && offset.is_none() {
            entry.position = read_offset.checked_add(read).unwrap();
        }
        Ok(read)
    }

    pub(crate) fn write_without_position_update(
        entry: &ResolverEntry,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<(usize, usize), WriteError> {
        if entry.path_only {
            return Err(WriteError::NotForWriting);
        }
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(WriteError::NotAFile),
        };
        let seek_behavior = entry.seek_behavior;
        if !entry.write_allowed {
            return Err(WriteError::NotForWriting);
        }
        if let Some(controlling) = &entry.controlling_terminal {
            return Ok((controlling.terminal.write(buf)?, 0));
        }

        let write_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased if entry.append_mode && offset.is_none() => {
                usize::try_from(
                    entry
                        .mount
                        .backend()
                        .status(HandleRef::File(file))
                        .map_err(|_| WriteError::Io)?
                        .size,
                )
                .map_err(|_| WriteError::Io)?
            }
            SeekBehavior::PositionBased => offset.unwrap_or(entry.position),
        };
        let written = entry.mount.backend().write(file, buf, write_offset)?;
        Ok((written, write_offset))
    }

    /// Write from a buffer to a file descriptor at `offset`
    ///
    /// If `offset` is None, the write will start at the current file offset and update the file
    /// offset to the end of the write.
    /// If `offset` is Some, the file offset is not changed.
    ///
    /// # Panics
    ///
    /// Panics if the updated file offset would overflow `usize`.
    pub fn write(
        &self,
        entry: &mut ResolverEntry,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let (written, write_offset) = Self::write_without_position_update(entry, buf, offset)?;
        if entry.uses_position() && offset.is_none() {
            entry.position = write_offset.checked_add(written).unwrap();
        }
        Ok(written)
    }

    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    pub fn seek(
        &self,
        entry: &mut ResolverEntry,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(SeekError::NotAFile),
        };
        if entry.path_only {
            return Err(SeekError::NotOpenForSeeking);
        }

        match entry.seek_behavior {
            SeekBehavior::NonSeekable => Err(SeekError::NonSeekable),
            SeekBehavior::ZeroPosition => Ok(0),
            SeekBehavior::PositionBased => {
                let file_len = entry
                    .mount
                    .backend()
                    .status(HandleRef::File(file))
                    .map_err(|_| SeekError::Io)?
                    .size;
                let file_len = usize::try_from(file_len).map_err(|_| SeekError::InvalidOffset)?;
                let base = match whence {
                    SeekWhence::RelativeToBeginning => 0,
                    SeekWhence::RelativeToCurrentOffset => entry.position,
                    SeekWhence::RelativeToEnd => file_len,
                };
                let new_position = base
                    .checked_add_signed(offset)
                    .ok_or(SeekError::InvalidOffset)?;
                // TODO(jayb): Linux allows regular files to seek past EOF, while some backends or
                // file types may not. Model that distinction instead of using one resolver rule.
                if new_position > file_len {
                    return Err(SeekError::InvalidOffset);
                }
                entry.position = new_position;
                Ok(new_position)
            }
        }
    }

    pub(crate) fn seek_without_position_update(entry: &ResolverEntry) -> Result<usize, SeekError> {
        match &entry.handle {
            Handle::File(_) => {}
            Handle::Dir(_) => return Err(SeekError::NotAFile),
        }
        if entry.path_only {
            return Err(SeekError::NotOpenForSeeking);
        }

        match entry.seek_behavior {
            SeekBehavior::NonSeekable => Err(SeekError::NonSeekable),
            SeekBehavior::ZeroPosition => Ok(0),
            SeekBehavior::PositionBased => {
                unreachable!("position-based seeks require exclusive resolver-entry access")
            }
        }
    }

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    ///
    /// If `reset_offset` is true, the offset is reset to zero; otherwise, it remains unchanged.
    pub fn truncate(
        &self,
        entry: &mut ResolverEntry,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        Self::truncate_without_position_update(entry, length)?;
        if reset_offset {
            entry.position = 0;
        }
        Ok(())
    }

    pub(crate) fn truncate_without_position_update(
        entry: &ResolverEntry,
        length: usize,
    ) -> Result<(), TruncateError> {
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(TruncateError::IsDirectory),
        };
        if entry.path_only {
            return Err(TruncateError::NotOpenForWriting);
        }
        if !entry.write_allowed {
            return Err(TruncateError::NotForWriting);
        }

        entry.mount.backend().truncate(file, length)?;
        Ok(())
    }

    /// Change timestamps of the object identified by an open entry.
    pub fn set_times(
        &self,
        user: UserInfo,
        entry: &ResolverEntry,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        // XXX: set_times re-resolves the open path as the caller;
        // renamed/unlinked/replaced open files fail with EIO, and losing search permission on an
        // ancestor fails with EACCES, where Linux updates the open inode.
        let context = Context::new(user);
        // Before resolving: the resolved target can hold a backend lock (e.g. the overlay's
        // namespace) that querying the open handle would take again.
        let opened = entry
            .mount
            .backend()
            .status(entry.handle.as_ref())
            .map_err(|_| SetTimesError::Io)?;
        let root = self.root();
        walk(
            &context,
            &root,
            &root,
            entry.path(),
            false,
            false,
            |location, resolution| {
                let Resolution::Found(target) = resolution else {
                    return Err(SetTimesError::Io);
                };
                let backend = location.mount.backend();
                let resolved = backend
                    .resolved_status(&target)
                    .map_err(|_| SetTimesError::Io)?;
                if (opened.node_info.dev, opened.node_info.ino)
                    != (resolved.node_info.dev, resolved.node_info.ino)
                {
                    return Err(SetTimesError::Io);
                }
                authorize_set_times(&context, &target, times)?;
                if matches!(
                    (times.access, times.modify),
                    (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
                ) {
                    return Ok(());
                }
                backend.set_times(target, times)
            },
        )
        .map_err(|error| match error {
            WalkError::Io
            | WalkError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            ) => SetTimesError::Io,
            WalkError::PathError(error) => SetTimesError::PathError(error),
        })?
    }

    /// Change the permissions of a file
    pub fn chmod(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), ChmodError> {
        let context = Context::new(user);
        let root = self.root();
        walk(
            &context,
            &root,
            &root,
            path,
            true,
            false,
            |location, resolution| {
                let Resolution::Found(target) = resolution else {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                };
                if !context.may_change_metadata(&target) {
                    return Err(ChmodError::NotTheOwner);
                }
                location.mount.backend().chmod(target, mode)
            },
        )
        .map_err(|error| match error {
            WalkError::Io => ChmodError::Io,
            WalkError::PathError(error) => error.into(),
        })?
    }

    /// Change the owner of a file
    pub fn chown(
        &self,
        acting_user: UserInfo,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = Context::new(acting_user);
        let root = self.root();
        walk(
            &context,
            &root,
            &root,
            path,
            true,
            false,
            |location, resolution| {
                let Resolution::Found(target) = resolution else {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                };
                if !context.may_change_metadata(&target) {
                    return Err(ChownError::NotTheOwner);
                }
                location.mount.backend().chown(target, user, group)
            },
        )
        .map_err(|error| match error {
            WalkError::Io => ChownError::Io,
            WalkError::PathError(error) => error.into(),
        })?
    }

    /// Unlink a file
    pub fn unlink(&self, user: UserInfo, path: &str) -> Result<(), UnlinkError> {
        let context = Context::new(user);
        let trailing_slash = path.ends_with('/');
        with_parent(&context, &self.root(), path, |mount, parent, name| {
            if matches!(name, "." | "..") {
                return Err(UnlinkError::IsADirectory);
            }
            let writable = context.check_dir_entries_change(
                &parent,
                UnlinkError::ReadOnlyFileSystem,
                UnlinkError::NoWritePerms,
            );
            // Linux checks for a read-only mount before looking up the name.
            if matches!(writable, Err(UnlinkError::ReadOnlyFileSystem)) {
                return writable;
            }
            let backend = mount.backend();
            if trailing_slash {
                // Only a directory may be named with a trailing slash, and unlink cannot remove
                // one.
                return Err(
                    match backend.resolve(parent, &[name], &|permissions| {
                        context.check_search_permission(permissions)
                    }) {
                        Ok(Resolution::Found(ResolvedTarget::Dir(_))) => UnlinkError::IsADirectory,
                        Ok(Resolution::Found(ResolvedTarget::File(_))) => {
                            PathError::ComponentNotADirectory.into()
                        }
                        Ok(Resolution::MissingFinal { .. }) => {
                            PathError::NoSuchFileOrDirectory.into()
                        }
                        Err(error) => match error.error {
                            WalkError::Io => UnlinkError::Io,
                            WalkError::PathError(error) => error.into(),
                        },
                    },
                );
            }
            if let Err(error) = writable {
                return Err(
                    if matches!(name_exists(&context, mount, parent, name), Ok(false)) {
                        PathError::NoSuchFileOrDirectory.into()
                    } else {
                        error
                    },
                );
            }
            backend.unlink_at(parent, name)
        })
        .map_err(|error| match error {
            WalkError::Io => UnlinkError::Io,
            WalkError::PathError(error) => error.into(),
        })?
        .unwrap_or(Err(UnlinkError::IsADirectory))
    }

    /// Create a symbolic link without resolving its target.
    pub fn symlink(
        &self,
        user: UserInfo,
        target: &str,
        linkpath: &str,
    ) -> Result<(), SymlinkError> {
        if target.is_empty() {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if target.as_bytes().contains(&0) || linkpath.as_bytes().contains(&0) {
            return Err(PathError::InvalidPathname.into());
        }
        let context = Context::new(user);
        let root = self.root();
        let result = with_parent(&context, &root, linkpath, |mount, parent, name| {
            if matches!(name, "." | "..") {
                return Err(SymlinkError::AlreadyExists);
            }
            let backend = mount.backend();
            if let Err(error) = context.check_dir_entries_change(
                &parent,
                SymlinkError::ReadOnlyFileSystem,
                SymlinkError::NoWritePerms,
            ) {
                return Err(
                    if matches!(name_exists(&context, mount, parent, name), Ok(true)) {
                        SymlinkError::AlreadyExists
                    } else {
                        error
                    },
                );
            }
            backend.symlink_at(
                parent,
                name,
                target,
                CreationMetadata {
                    mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                    owner: context.acting_user(),
                },
            )
        })
        .map_err(|error| match error {
            WalkError::Io => SymlinkError::Io,
            WalkError::PathError(error) => error.into(),
        })?
        .unwrap_or(Err(SymlinkError::AlreadyExists));
        // Backends refuse writes without checking the name.
        if let Err(SymlinkError::ReadOnlyFileSystem) = result
            && let Ok(Some(Ok(true))) =
                with_parent(&context, &root, linkpath, |mount, parent, name| {
                    name_exists(&context, mount, parent, name)
                })
        {
            return Err(SymlinkError::AlreadyExists);
        }
        result
    }

    /// Atomically move an entry to a new name, replacing a compatible destination.
    ///
    /// Parent symbolic links are resolved, but final symbolic links are moved themselves.
    pub fn rename(
        &self,
        user: UserInfo,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), RenameError> {
        let context = Context::new(user);
        let map_walk_error = |error| match error {
            WalkError::Io => RenameError::Io,
            WalkError::PathError(error) => error.into(),
        };
        let root = self.root();
        let parent = |path: &str| {
            if path.is_empty() {
                return Err(PathError::NoSuchFileOrDirectory.into());
            }
            if path.contains('\0') {
                return Err(PathError::InvalidPathname.into());
            }
            with_parent(&context, &root, path, |mount, parent, name| {
                if matches!(name, "." | "..") {
                    return Err(RenameError::Busy);
                }
                let writable = context.check_dir_entries_change(
                    &parent,
                    RenameError::ReadOnlyFileSystem,
                    RenameError::NoWritePerms,
                );
                // Own this directory before walking the other parent: walking handles may retain
                // locks.
                let dir = mount
                    .backend()
                    .open_dir(parent, OFlags::PATH)
                    .map_err(|error| match error {
                        OpenError::PathError(error) => RenameError::PathError(error),
                        OpenError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                        OpenError::NoWritePerms | OpenError::AccessNotAllowed => {
                            RenameError::NoWritePerms
                        }
                        _ => RenameError::Io,
                    })?;
                Ok((Arc::clone(mount), dir, String::from(name), writable))
            })
            .map_err(map_walk_error)?
            .unwrap_or(Err(RenameError::Busy))
        };
        let (old_mount, old_dir, old_name, old_writable) = parent(old_path)?;
        let (new_mount, new_dir, new_name, new_writable) = parent(new_path)?;
        // Linux checks for a cross-mount rename, then for a read-only mount, before looking up
        // either name.
        if !Arc::ptr_eq(&old_mount, &new_mount) {
            return Err(RenameError::CrossDevice);
        }
        let backend = old_mount.backend();
        // Only the backend knows whether the directories are on different backends it is made
        // of; asking it relies on every backend that sets `on_read_only_fs` (TarRo, ReadOnly,
        // Composer virtual directories) refusing the rename without mutating anything.
        if [&old_writable, &new_writable]
            .into_iter()
            .any(|writable| matches!(writable, Err(RenameError::ReadOnlyFileSystem)))
        {
            return match backend.rename_at(old_dir, &old_name, new_dir, &new_name) {
                Err(RenameError::CrossDevice) => Err(RenameError::CrossDevice),
                _ => Err(RenameError::ReadOnlyFileSystem),
            };
        }
        // A trailing slash on either path requires the source to be a directory; backends already
        // require a directory source to replace only a directory.
        let require_directory = old_path.ends_with('/') || new_path.ends_with('/');
        // XXX(jayb): like unlink, this source lookup isn't atomic with the rename; fix as part of
        // broader atomicity fixups.
        if require_directory || old_writable.is_err() || new_writable.is_err() {
            let walking = backend.walking_dir_at(&old_dir).ok_or(RenameError::Io)?;
            match backend
                .resolve(walking, &[&old_name], &|permissions| {
                    context.check_search_permission(permissions)
                })
                .map_err(|error| map_walk_error(error.error))?
            {
                Resolution::Found(ResolvedTarget::File(_)) if require_directory => {
                    return Err(PathError::ComponentNotADirectory.into());
                }
                Resolution::Found(_) => {}
                Resolution::MissingFinal { .. } => {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                }
            }
        }
        old_writable.and(new_writable)?;
        // XXX(jayb): like unlink, rename omits sticky-bit checks and write permission on a moved
        // directory for updating `..`.
        backend.rename_at(old_dir, &old_name, new_dir, &new_name)
    }

    /// Create a new directory
    pub fn mkdir(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), MkdirError> {
        let context = Context::new(user);
        let root = self.root();
        let result = with_parent(&context, &root, path, |mount, parent, name| {
            if matches!(name, "." | "..") {
                return Err(MkdirError::AlreadyExists);
            }
            let backend = mount.backend();
            if let Err(error) = context.check_dir_entries_change(
                &parent,
                MkdirError::ReadOnlyFileSystem,
                MkdirError::NoWritePerms,
            ) {
                return Err(
                    if matches!(name_exists(&context, mount, parent, name), Ok(true)) {
                        MkdirError::AlreadyExists
                    } else {
                        error
                    },
                );
            }
            backend
                .mkdir_at(
                    parent,
                    name,
                    CreationMetadata {
                        mode,
                        owner: context.acting_user(),
                    },
                )
                .map(|_| ())
        })
        .map_err(|error| match error {
            WalkError::Io => MkdirError::Io,
            WalkError::PathError(error) => error.into(),
        })?
        .unwrap_or(Err(MkdirError::AlreadyExists));
        // Backends refuse writes without checking the name.
        if let Err(MkdirError::ReadOnlyFileSystem) = result
            && let Ok(Some(Ok(true))) = with_parent(&context, &root, path, |mount, parent, name| {
                name_exists(&context, mount, parent, name)
            })
        {
            return Err(MkdirError::AlreadyExists);
        }
        result
    }

    /// Remove a directory
    pub fn rmdir(&self, user: UserInfo, path: &str) -> Result<(), RmdirError> {
        let context = Context::new(user);
        with_parent(&context, &self.root(), path, |mount, parent, name| {
            match name {
                "." => return Err(PathError::InvalidPathname.into()),
                ".." => return Err(RmdirError::NotEmpty),
                _ => {}
            }
            let writable = context.check_dir_entries_change(
                &parent,
                RmdirError::ReadOnlyFileSystem,
                RmdirError::NoWritePerms,
            );
            // Linux checks for a read-only mount before looking up the name.
            if matches!(writable, Err(RmdirError::ReadOnlyFileSystem)) {
                return writable;
            }
            if let Err(error) = writable {
                return Err(
                    if matches!(name_exists(&context, mount, parent, name), Ok(false)) {
                        PathError::NoSuchFileOrDirectory.into()
                    } else {
                        error
                    },
                );
            }
            mount.backend().rmdir_at(parent, name)
        })
        .map_err(|error| match error {
            WalkError::Io => RmdirError::Io,
            WalkError::PathError(error) => error.into(),
        })?
        .unwrap_or(Err(RmdirError::Busy))
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names including synthesized `.` and `..` entries.
    pub fn read_dir(&self, entry: &ResolverEntry) -> Result<Vec<super::DirEntry>, ReadDirError> {
        if entry.path_only {
            return Err(ReadDirError::NotOpenForReading);
        }
        let dir = match &entry.handle {
            Handle::File(_) => return Err(ReadDirError::NotADirectory),
            Handle::Dir(dir) => dir,
        };

        let mut entries = Vec::new();
        // TODO(jayb): Fill in inode info for synthesized dot entries.
        entries.push(super::DirEntry {
            name: String::from("."),
            file_type: FileType::Directory,
            ino_info: None,
        });
        entries.push(super::DirEntry {
            name: String::from(".."),
            file_type: FileType::Directory,
            ino_info: None,
        });
        entries.extend(entry.mount.backend().list_dir_at(dir.clone())?);
        Ok(entries)
    }

    /// Obtain the status of a file/directory/... on the file-system.
    ///
    /// If `follow_symlinks` is false, a final symbolic link is described itself.
    pub fn file_status(
        &self,
        user: UserInfo,
        path: &str,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, FileStatusError> {
        let root = self.root();
        walk(
            &Context::new(user),
            &root,
            &root,
            path,
            follow_symlinks,
            false,
            |location, resolution| {
                let Resolution::Found(target) = resolution else {
                    return Err(PathError::NoSuchFileOrDirectory.into());
                };
                // Unlike an O_PATH open, this must not trigger backend open hooks.
                location.mount.backend().resolved_status(&target)
            },
        )
        .map_err(|error| match error {
            WalkError::Io => FileStatusError::Io,
            WalkError::PathError(error) => error.into(),
        })?
    }

    /// Equivalent to [`Self::file_status`], but on an open entry instead.
    pub fn handle_status(
        &self,
        entry: &ResolverEntry,
    ) -> Result<super::FileStatus, FileStatusError> {
        entry.mount.backend().status(entry.handle.as_ref())
    }

    /// Applies, or fails without blocking, an advisory whole-file lock held by the open
    /// description `owner`.
    ///
    /// Conflicts fail with [`BrokerError::NonBlockingWouldBlock`](crate::BrokerError), since
    /// waiting in the broker could block the request that unlocks.
    pub(super) fn lock(
        &self,
        entry: &ResolverEntry,
        owner: &Arc<dyn core::any::Any + Send + Sync>,
        operation: FileLockOperation,
    ) -> crate::Result<Result<(), FileStatusError>> {
        let request = match operation {
            FileLockOperation::Shared | FileLockOperation::Exclusive => {
                // TODO(jayb): overlay dir flock identity follows the stored path; after a
                // rename-while-open it may lock the wrong dir or fail.
                let status = match self.handle_status(entry) {
                    Ok(status) => status,
                    Err(error) => return Ok(Err(error)),
                };
                Some(((status.node_info.dev, status.node_info.ino), operation))
            }
            FileLockOperation::Unlock => None,
        };
        if !self.flocks.set(owner, request)? {
            return Err(crate::BrokerError::NonBlockingWouldBlock);
        }
        Ok(Ok(()))
    }

    /// Shared terminal backing a non-path-only entry.
    pub fn terminal(&self, entry: &ResolverEntry) -> Option<Arc<dyn TerminalEndpoint>> {
        match &entry.handle {
            Handle::File(file) if !entry.path_only => match entry.mount.backend().terminal(file)? {
                FileTerminal::Fixed(terminal) => Some(terminal),
                FileTerminal::OpenersControlling => entry
                    .controlling_terminal
                    .as_ref()
                    .map(|controlling| Arc::clone(&controlling.terminal)),
            },
            Handle::File(_) | Handle::Dir(_) => None,
        }
    }

    /// Readiness of an open entry whose reads or writes can fail with `WouldBlock`, or `None` if
    /// they always make progress. Path-only entries never read or write.
    pub fn readiness_source(&self, entry: &ResolverEntry) -> Option<Arc<dyn ReadinessSource>> {
        if let Some(controlling) = &entry.controlling_terminal {
            return Some(Arc::clone(&controlling.terminal) as Arc<dyn ReadinessSource>);
        }
        match &entry.handle {
            Handle::File(file) if !entry.path_only => entry.mount.backend().readiness_source(file),
            Handle::File(_) | Handle::Dir(_) => None,
        }
    }

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., set up via [`super::in_mem::InitialNode::File`]).
    ///
    /// Returns `None` if no static backing data is available/supported.
    pub fn get_static_backing_data(&self, entry: &ResolverEntry) -> Option<&'static [u8]> {
        match &entry.handle {
            Handle::File(file) => entry.mount.backend().get_static_backing_data(file),
            Handle::Dir(_) => None,
        }
    }

    /// Returns the host shared object holding an open file's contents, for a `MAP_SHARED`
    /// mapping, and whether it may be mapped writable.
    ///
    /// The file must be open for reading, and the object may be mapped writable exactly when the
    /// file is open for writing too, as Linux allows of a shared mapping that `mprotect` may
    /// later make writable.
    pub fn map_shared(
        &self,
        entry: &ResolverEntry,
    ) -> Result<super::shared_storage::SharedMapping, MapSharedError> {
        // An `O_PATH` descriptor cannot be mapped whatever it names, as Linux fails `mmap` of
        // one with `EBADF`.
        if entry.path_only {
            return Err(MapSharedError::PathOnly);
        }
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(MapSharedError::IsDirectory),
        };
        if !entry.read_allowed {
            return Err(MapSharedError::NotForReading);
        }
        let file = entry.mount.backend().map_shared(file)?;
        Ok(super::shared_storage::SharedMapping {
            file,
            writable: entry.write_allowed,
        })
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "resolver fd entries carry independent descriptor flags"
)]
/// Authoritative resolver-owned state for one open filesystem entry.
pub struct ResolverEntry {
    handle: Handle,
    /// The mount the entry was opened on, whose backend `handle` belongs to.
    mount: Arc<Mount>,
    read_allowed: bool,
    write_allowed: bool,
    position: usize,
    append_mode: bool,
    /// Whether reads and writes that would block fail instead of waiting.
    nonblocking: bool,
    path_only: bool,
    seek_behavior: SeekBehavior,
    /// Absolute path of the opened object, with symbolic links resolved, as of when it was opened.
    ///
    /// Later renames or removals of the object are not reflected.
    path: String,
    /// The controlling terminal that the file referred to when it was opened,
    /// if it refers to the opener's (see [`FileTerminal::OpenersControlling`]).
    controlling_terminal: Option<ReopenedTerminal>,
}

/// A terminal reopened by [`TerminalEndpoint::reopen`], which stays open
/// until this drops.
struct ReopenedTerminal {
    terminal: Arc<dyn TerminalEndpoint>,
    _file: Box<dyn Send + Sync>,
}

impl ResolverEntry {
    pub(crate) const fn is_path_only(&self) -> bool {
        self.path_only
    }

    /// Absolute path of the opened object, with symbolic links resolved, as of when it was opened.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) const fn allows_read(&self) -> bool {
        self.read_allowed
    }

    pub(crate) const fn allows_write(&self) -> bool {
        self.write_allowed
    }

    pub(crate) const fn is_append(&self) -> bool {
        self.append_mode
    }

    pub(crate) fn set_append(&mut self, append: bool) {
        self.append_mode = append;
    }

    pub(crate) const fn is_nonblocking(&self) -> bool {
        self.nonblocking
    }

    pub(crate) fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    pub(crate) const fn uses_position(&self) -> bool {
        matches!(self.seek_behavior, SeekBehavior::PositionBased)
    }
}
