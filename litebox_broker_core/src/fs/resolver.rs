// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Path management, permission checks, and open-state operations above [`super::backend`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;

use litebox_broker_protocol::fs::FileLockOperation;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::RawSyncPrimitivesProvider;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SeekError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{
    FileTimeUpdate, FileType, Mode, OFlags, SetFileTimes,
    backend::{
        CreationMetadata, DirHandle, FileTerminal, Handle, HandleRef, PermissionCheck,
        PermissionInfo, Resolution, ResolvedDir, ResolvedTarget, SeekBehavior,
    },
};
use super::{SeekWhence, UserInfo};
use crate::readiness::ReadinessSource;
use crate::terminal::TerminalEndpoint;

/// Maximum number of symbolic links followed while resolving a single path; following more fails
/// with [`PathError::TooManySymlinks`].
const MAX_SYMLINKS: usize = 40;

/// The broker-core filesystem resolver, generic over its synchronization platform and
/// [`Backend`](super::backend::Backend).
pub struct Resolver<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
{
    backend: Backend,
    flocks: super::flock::FlockTable<Platform>,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a filesystem resolver over `backend`.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            flocks: super::flock::FlockTable::new(),
            _sync: PhantomData,
        }
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
}

#[derive(Clone)]
struct WalkAnchor {
    dir: DirHandle,
    /// Name recorded when `dir` was opened, used only when the backend cannot name `dir`.
    /// It may be stale after a rename.
    hint: String,
}

/// An open entry captured as the starting point of a relative lookup (see
/// [`ResolverEntry::anchor`]).
#[derive(Clone)]
pub struct DirAnchor(Option<WalkAnchor>);

/// Normalized components relative to a held directory, or to root if unanchored.
struct ResolvedPath {
    anchor: Option<WalkAnchor>,
    components: Vec<String>,
}

impl ResolvedPath {
    /// The path as an absolute string, naming any anchor by its recorded hint.
    fn to_absolute(&self) -> String {
        let base = self
            .anchor
            .as_ref()
            .map_or("", |anchor| anchor.hint.trim_end_matches('/'));
        Self::join(String::from(base), &self.components)
    }

    fn join(mut path: String, components: &[String]) -> String {
        for component in components {
            path.push('/');
            path.push_str(component);
        }
        if path.is_empty() {
            return String::from("/");
        }
        path
    }

    fn parent_and_name(&self) -> Option<(Vec<&str>, &str)> {
        let (name, parent) = self.components.split_last()?;
        Some((parent.iter().map(String::as_str).collect(), name.as_str()))
    }
}

impl<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Mount a fresh in-memory filesystem on an existing directory.
    // XXX(jayb): Once guests can request other mount kinds, replace this with a mount taking the
    // requested kind; the permission checks here are backend-independent.
    pub fn mount_in_mem(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<(), litebox_broker_protocol::fs::FileError> {
        use super::composer::{Composer, MountError};
        use super::in_mem::{InMem, InitialNode};
        use super::service::file_walk_error;
        use litebox_broker_protocol::fs::FileError;

        let context = Context::new(user);
        let (path, walked) = self
            .resolve_path(&context, None, path, true, false)
            .map_err(file_walk_error)?;
        let ResolvedTarget::Dir(target) = self
            .resolve_target(&context, &path, walked)
            .map_err(file_walk_error)?
        else {
            return Err(FileError::NotDirectory);
        };
        if user.user != UserInfo::ROOT.user {
            // XXX(jayb): Linux requires CAP_SYS_ADMIN; we let non-root mount over directories they own.
            if !matches!(&target.permissions, PermissionCheck::ByResolver(info) if info.owner.user == user.user)
            {
                return Err(FileError::NotOwner);
            }
            // Overlay walking handles hold its namespace lock; release it before rewalking.
            drop(target);
            // XXX(jayb): Path-based mount can race renames; refusing foreign sticky ancestors is a
            // stopgap.
            for len in 0..path.components.len() {
                let components: Vec<_> =
                    path.components[..len].iter().map(String::as_str).collect();
                let Resolution::Found(ResolvedTarget::Dir(ancestor)) = self
                    .resolve_components(&context, path.anchor.as_ref(), &components)
                    .map_err(|error| file_walk_error(error.error))?
                else {
                    return Err(FileError::NotOwner);
                };
                match ancestor.permissions {
                    PermissionCheck::ByResolver(info)
                        if info.owner.user == user.user || !info.mode.contains(Mode::SVTX) => {}
                    _ => return Err(FileError::NotOwner),
                }
            }
        }
        let composer = (&self.backend as &dyn core::any::Any)
            .downcast_ref::<Composer<Platform>>()
            .ok_or(FileError::NotSupported)?;
        composer
            .mount(&path.to_absolute(), |allocator| {
                InMem::<Platform>::new_initialized(
                    [(
                        "/",
                        InitialNode::Directory {
                            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO | Mode::SVTX,
                            owner: user,
                        },
                    )],
                    allocator,
                )
            })
            .map_err(|error| match error {
                MountError::InvalidMountPath => FileError::InvalidPathname,
                MountError::Busy => FileError::Busy,
                MountError::NoSpace => FileError::NoSpace,
            })
    }

    /// Also returns the final resolution of the path when its last step was a walk, so callers
    /// need not walk again. A path ending in `.` or `..`, or naming the walk start itself, has
    /// none; [`Self::final_resolution`] rewalks those.
    // XXX(jayb): if/when we support chroot, we might need to tweak this to not allow "escaping"
    // outside the chrooted part.
    fn resolve_path(
        &self,
        context: &Context,
        anchor: Option<DirAnchor>,
        path: &str,
        follow_final: bool,
        allow_missing: bool,
    ) -> Result<(ResolvedPath, Option<Resolution<'_>>), WalkError> {
        if path.is_empty() {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        let mut anchor = match anchor.filter(|_| !path.starts_with('/')) {
            Some(DirAnchor(Some(anchor))) => Some(anchor),
            Some(DirAnchor(None)) => return Err(PathError::ComponentNotADirectory.into()),
            None => None,
        };
        let mut pending: VecDeque<String> = path
            .split('/')
            .filter(|part| !part.is_empty())
            .map(String::from)
            .collect();
        let mut require_directory = path.ends_with('/');
        let mut resolved: Vec<String> = Vec::new();
        let mut links = 0;
        // Kept only once nothing is pending, so no walking handle (which may hold a backend
        // lock) outlives its run while another walk starts.
        let mut walked = None;
        // Each run re-resolves from the same held directory, since `Backend::resolve` consumes its
        // starting directory and does not report symlinks mid-walk.
        while let Some(name) = pending.front() {
            match name.as_str() {
                "." => {
                    pending.pop_front();
                    // Any later component checks search permission on the start itself.
                    if resolved.is_empty() && pending.is_empty() {
                        self.check_start_search(context, anchor.as_ref())?;
                    }
                    continue;
                }
                ".." => {
                    pending.pop_front();
                    // The remaining prefix was already resolved (and search-checked) above.
                    if resolved.pop().is_none() {
                        self.check_start_search(context, anchor.as_ref())?;
                        if let Some(base) = &mut anchor {
                            match self.backend.parent_dir(&base.dir)? {
                                Some(parent) => {
                                    base.dir = parent;
                                    base.hint.truncate(base.hint.rfind('/').unwrap_or(0));
                                }
                                None => anchor = None,
                            }
                        }
                    }
                    continue;
                }
                _ => {}
            }
            let run_len = pending
                .iter()
                .take_while(|part| !matches!(part.as_str(), "." | ".."))
                .count();
            let run_start = resolved.len();
            resolved.extend(pending.drain(..run_len));
            let mut end = resolved.len();
            let resolution = loop {
                let components: Vec<_> = resolved[..end].iter().map(String::as_str).collect();
                match self.resolve_components(context, anchor.as_ref(), &components) {
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
            for part in resolved.drain(end..).rev() {
                pending.push_front(part);
            }
            let final_component = pending.is_empty();
            match resolution {
                Resolution::Found(ResolvedTarget::Dir(dir)) => {
                    if final_component {
                        walked = Some(Resolution::Found(ResolvedTarget::Dir(dir)));
                    } else {
                        // `sub/../f` must still require search permission on `sub`.
                        self.check_dir_search(context, &dir)?;
                    }
                }
                Resolution::Found(ResolvedTarget::File(file))
                    if file.file_type == FileType::SymbolicLink =>
                {
                    if final_component && !follow_final && !require_directory {
                        walked = Some(Resolution::Found(ResolvedTarget::File(file)));
                        break;
                    }
                    // TODO(jayb): add a resolved-file read_link to avoid re-resolving the parent.
                    drop(file);
                    links += 1;
                    if links > MAX_SYMLINKS {
                        return Err(PathError::TooManySymlinks.into());
                    }
                    let name = resolved
                        .pop()
                        .expect("symlink is the last resolved component");
                    let parent_components: Vec<_> = resolved.iter().map(String::as_str).collect();
                    let Resolution::Found(ResolvedTarget::Dir(parent)) = self
                        .resolve_components(context, anchor.as_ref(), &parent_components)
                        .map_err(|error| error.error)?
                    else {
                        return Err(PathError::MissingComponent.into());
                    };
                    let target = self.backend.read_link_at(&parent, &name)?;
                    if target.starts_with('/') {
                        resolved.clear();
                        anchor = None;
                    }
                    if final_component && target.ends_with('/') {
                        // XXX(jayb): O_CREAT should reject an ordinary final name with EISDIR
                        // even when the trailing slash comes from the link target.
                        require_directory = true;
                    }
                    for part in target.split('/').filter(|part| !part.is_empty()).rev() {
                        pending.push_front(String::from(part));
                    }
                }
                Resolution::Found(ResolvedTarget::File(file)) => {
                    if !final_component || require_directory {
                        return Err(PathError::ComponentNotADirectory.into());
                    }
                    walked = Some(Resolution::Found(ResolvedTarget::File(file)));
                }
                Resolution::MissingFinal { parent } => {
                    if final_component && allow_missing && !require_directory {
                        walked = Some(Resolution::MissingFinal { parent });
                        break;
                    }
                    return Err(if final_component {
                        PathError::NoSuchFileOrDirectory
                    } else {
                        PathError::MissingComponent
                    }
                    .into());
                }
            }
        }
        Ok((
            ResolvedPath {
                anchor,
                components: resolved,
            },
            walked,
        ))
    }

    /// The resolution of `path`, reusing `walked` from [`Self::resolve_path`] when present.
    fn final_resolution<'a>(
        &'a self,
        context: &Context,
        path: &ResolvedPath,
        walked: Option<Resolution<'a>>,
    ) -> Result<Resolution<'a>, WalkError> {
        if let Some(resolution) = walked {
            return Ok(resolution);
        }
        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        self.resolve_components(context, path.anchor.as_ref(), &components)
            .map_err(|error| error.error)
    }

    fn parent_dir_and_name(
        &self,
        context: &Context,
        anchor: Option<DirAnchor>,
        path: &str,
    ) -> Result<Option<(ResolvedDir<'_>, String)>, WalkError> {
        if path.is_empty() {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        // Keep scoped resolution state alive across the mutation so backend locks stay held.
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Ok(None);
        }
        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some(parts) => parts,
            None => (".", trimmed),
        };
        // Entry mutations resolve the parent but retain the final name, so neither a link nor
        // a final `.`/`..` can redirect a removal to an ordinary target directory.
        let (parent_path, walked) = self.resolve_path(context, anchor, parent_path, true, false)?;
        let parent = match self.final_resolution(context, &parent_path, walked)? {
            Resolution::Found(ResolvedTarget::Dir(parent)) => parent,
            Resolution::Found(ResolvedTarget::File(_)) => {
                return Err(PathError::ComponentNotADirectory.into());
            }
            Resolution::MissingFinal { .. } => return Err(PathError::MissingComponent.into()),
        };
        if let PermissionCheck::ByResolver(permissions) = &parent.permissions {
            Self::check_search_permission(context, permissions)?;
        }
        Ok(Some((parent, String::from(name))))
    }

    fn name_exists<'a>(
        &'a self,
        context: &Context,
        parent: ResolvedDir<'a>,
        name: &str,
    ) -> Result<bool, WalkError> {
        let resolution = self
            .backend
            .resolve(parent, &[name], &|permissions| {
                Self::check_search_permission(context, permissions)
            })
            .map_err(|error| error.error)?;
        Ok(matches!(resolution, Resolution::Found(_)))
    }

    /// Read a symbolic link's stored target, without following the final link. A relative
    /// `path` is resolved from `anchor`, or from the root without one.
    pub fn read_link(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
    ) -> Result<String, WalkError> {
        let context = Context::new(user);
        let (path, walked) = self.resolve_path(&context, anchor, path, false, false)?;
        let Some((components, name)) = path.parent_and_name() else {
            return Err(PathError::InvalidPathname.into());
        };
        // Released before walking to the parent.
        let is_link = matches!(
            self.final_resolution(&context, &path, walked)?,
            Resolution::Found(ResolvedTarget::File(file))
                if file.file_type == FileType::SymbolicLink
        );
        if !is_link {
            return Err(PathError::InvalidPathname.into());
        }
        let Resolution::Found(ResolvedTarget::Dir(parent)) = self
            .resolve_components(&context, path.anchor.as_ref(), &components)
            .map_err(|error| error.error)?
        else {
            return Err(PathError::MissingComponent.into());
        };
        self.backend.read_link_at(&parent, name)
    }

    /// Check that `context` may add or remove entries in `dir`: `read_only` if `dir` is on a
    /// read-only filesystem, whatever its mode (Linux checks the mount before permissions), else
    /// `no_write_perms` if `context` can't write `dir`.
    fn check_dir_entries_change<E>(
        context: &Context,
        dir: &ResolvedDir<'_>,
        read_only: E,
        no_write_perms: E,
    ) -> Result<(), E> {
        match &dir.permissions {
            PermissionCheck::ByResolver(permissions) if permissions.on_read_only_fs => {
                Err(read_only)
            }
            PermissionCheck::ByResolver(permissions) if !context.can_write(permissions) => {
                Err(no_write_perms)
            }
            PermissionCheck::ByBackend | PermissionCheck::ByResolver(_) => Ok(()),
        }
    }

    fn resolve_target<'a>(
        &'a self,
        context: &Context,
        path: &ResolvedPath,
        walked: Option<Resolution<'a>>,
    ) -> Result<ResolvedTarget<'a>, WalkError> {
        match self.final_resolution(context, path, walked)? {
            Resolution::Found(target) => Ok(target),
            Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    fn check_search_permission(
        context: &Context,
        permissions: &PermissionInfo,
    ) -> Result<(), WalkError> {
        if !context.can_execute(permissions) {
            litebox_util_log::debug!(perms:? = permissions.mode; "no search permission");
            return Err(PathError::NoSearchPerms.into());
        }
        Ok(())
    }

    fn walk_start(&self, anchor: Option<&WalkAnchor>) -> Result<ResolvedDir<'_>, WalkError> {
        match anchor {
            None => self.backend.root(),
            Some(anchor) => self.backend.walking_dir_at(&anchor.dir),
        }
    }

    fn check_start_search(
        &self,
        context: &Context,
        anchor: Option<&WalkAnchor>,
    ) -> Result<(), WalkError> {
        self.check_dir_search(context, &self.walk_start(anchor)?)
    }

    fn check_dir_search(&self, context: &Context, dir: &ResolvedDir<'_>) -> Result<(), WalkError> {
        match &dir.permissions {
            PermissionCheck::ByResolver(perms) => Self::check_search_permission(context, perms),
            PermissionCheck::ByBackend => self.backend.check_search_permission(dir),
        }
    }

    fn resolve_components(
        &self,
        context: &Context,
        anchor: Option<&WalkAnchor>,
        components: &[&str],
    ) -> Result<Resolution<'_>, ResolutionError> {
        let start = self.walk_start(anchor).map_err(|error| ResolutionError {
            component: None,
            error,
        })?;
        self.backend
            .resolve(start, components, &|permissions| {
                Self::check_search_permission(context, permissions)
            })
            .map_err(|mut error| {
                if let Some(index) = error.component
                    && let WalkError::PathError(PathError::NoSearchPerms) = &error.error
                {
                    litebox_util_log::debug!(
                        dir:% = alloc::format!("/{}", components[..index].join("/"));
                        "no search permission"
                    );
                }
                if matches!(
                    error.error,
                    WalkError::PathError(PathError::NoSuchFileOrDirectory)
                ) && error
                    .component
                    .is_none_or(|index| index < components.len().saturating_sub(1))
                {
                    // TODO(jayb): keeps ENOENT for a final name hidden by Composer (see composer
                    // shadowed-file handling).
                    error.error = PathError::MissingComponent.into();
                }
                error
            })
    }
}

impl<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Opens a file. A relative `path` is resolved from `anchor`, or from the root without one.
    ///
    /// The `mode` is only significant when creating a file. Opening a file
    /// that refers to the opener's controlling terminal for I/O fails with
    /// [`OpenError::NoSuchDevice`], as if the opener had none (see
    /// [`open_with_controlling_terminal`](Self::open_with_controlling_terminal)).
    pub fn open(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<ResolverEntry<Backend>, OpenError> {
        self.open_with_controlling_terminal(user, anchor, path, flags, mode, &|| None)
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
        anchor: Option<DirAnchor>,
        path: &str,
        flags: OFlags,
        mode: Mode,
        controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
    ) -> Result<ResolverEntry<Backend>, OpenError> {
        let mut entry = self.open_entry(user, anchor, path, flags, mode)?;
        if let Handle::File(file) = &entry.handle
            && !entry.path_only
            && matches!(
                self.backend.terminal(file),
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
        anchor: Option<DirAnchor>,
        path: &str,
        mut flags: OFlags,
        mode: Mode,
    ) -> Result<ResolverEntry<Backend>, OpenError> {
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
        let trailing_create = flags.contains(OFlags::CREAT) && path.ends_with('/');
        if trailing_create
            && !matches!(
                path.trim_end_matches('/').rsplit('/').next(),
                Some("" | "." | "..")
            )
        {
            // Linux resolves the parent but rejects O_CREAT with a trailing slash before
            // looking up an ordinary final name (even when it is missing or a symlink).
            self.parent_dir_and_name(&context, anchor, path)
                .map_err(OpenError::from)?;
            return Err(OpenError::IsDirectory);
        }
        let (path, walked) = self
            .resolve_path(
                &context,
                anchor,
                path,
                !flags.contains(OFlags::NOFOLLOW) && !flags.contains(OFlags::CREAT | OFlags::EXCL),
                flags.contains(OFlags::CREAT),
            )
            .map_err(OpenError::from)?;
        if trailing_create && !flags.contains(OFlags::EXCL) {
            return Err(OpenError::IsDirectory);
        }
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let entry = |handle, seek_behavior, path: ResolvedPath| ResolverEntry {
            handle,
            _backend: core::marker::PhantomData,
            read_allowed,
            write_allowed,
            position: 0,
            append_mode,
            nonblocking,
            path_only,
            seek_behavior,
            name: path,
            controlling_terminal: None,
        };

        let resolution = self
            .final_resolution(&context, &path, walked)
            .map_err(OpenError::from)?;
        match resolution {
            Resolution::Found(_) if flags.contains(OFlags::CREAT | OFlags::EXCL) => {
                Err(OpenError::AlreadyExists)
            }
            Resolution::Found(ResolvedTarget::Dir(dir)) => {
                // XXX(jayb): non-read, non-PATH dir opens check search instead of read (#884/#888
                // workaround); Linux returns EISDIR for write opens.
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
                    Handle::Dir(self.backend.open_dir(dir, flags)?),
                    SeekBehavior::NonSeekable,
                    path,
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
                if !path_only && let PermissionCheck::ByResolver(permissions) = &file.permissions {
                    if wants_write && permissions.on_read_only_fs {
                        return Err(OpenError::ReadOnlyFileSystem);
                    }
                    if (read_allowed && !context.can_read(permissions))
                        || (wants_write && !context.can_write(permissions))
                    {
                        return Err(OpenError::AccessNotAllowed);
                    }
                }
                let file = self.backend.open_file(file, flags)?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(entry(Handle::File(file), seek_behavior, path))
            }
            Resolution::MissingFinal { parent } if flags.contains(OFlags::CREAT) => {
                let Some(name) = path.components.last() else {
                    // Empty components name the walk start (root or anchor), which always exists.
                    unreachable!()
                };
                if let PermissionCheck::ByResolver(permissions) = &parent.permissions {
                    Self::check_search_permission(&context, permissions)?;
                }
                Self::check_dir_entries_change(
                    &context,
                    &parent,
                    OpenError::ReadOnlyFileSystem,
                    OpenError::NoWritePerms,
                )?;
                let file = self.backend.create_file_at(
                    parent,
                    name,
                    CreationMetadata {
                        mode,
                        owner: context.acting_user(),
                    },
                )?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(entry(Handle::File(file), seek_behavior, path))
            }
            Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    pub(crate) fn read_without_position_update(
        &self,
        entry: &ResolverEntry<Backend>,
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
        let read = self.backend.read(file, buf, read_offset)?;
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
        entry: &mut ResolverEntry<Backend>,
        buf: &mut dyn ReadBuffer,
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let (read, read_offset) = self.read_without_position_update(entry, buf, offset)?;
        if entry.uses_position() && offset.is_none() {
            entry.position = read_offset.checked_add(read).unwrap();
        }
        Ok(read)
    }

    pub(crate) fn write_without_position_update(
        &self,
        entry: &ResolverEntry<Backend>,
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
                    self.backend
                        .status(HandleRef::File(file))
                        .map_err(|_| WriteError::Io)?
                        .size,
                )
                .map_err(|_| WriteError::Io)?
            }
            SeekBehavior::PositionBased => offset.unwrap_or(entry.position),
        };
        let written = self.backend.write(file, buf, write_offset)?;
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
        entry: &mut ResolverEntry<Backend>,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let (written, write_offset) = self.write_without_position_update(entry, buf, offset)?;
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
        entry: &mut ResolverEntry<Backend>,
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
                let file_len = self
                    .backend
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

    pub(crate) fn seek_without_position_update(
        entry: &ResolverEntry<Backend>,
    ) -> Result<usize, SeekError> {
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
        entry: &mut ResolverEntry<Backend>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        self.truncate_without_position_update(entry, length)?;
        if reset_offset {
            entry.position = 0;
        }
        Ok(())
    }

    pub(crate) fn truncate_without_position_update(
        &self,
        entry: &ResolverEntry<Backend>,
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

        self.backend.truncate(file, length)?;
        Ok(())
    }

    fn may_change_metadata(context: &Context, target: &ResolvedTarget<'_>) -> bool {
        let permissions = match target {
            ResolvedTarget::Dir(dir) => &dir.permissions,
            ResolvedTarget::File(file) => &file.permissions,
        };
        let PermissionCheck::ByResolver(permissions) = permissions else {
            return true;
        };
        let acting = context.acting_user();
        acting.user == UserInfo::ROOT.user || acting.user == permissions.owner.user
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
        if Self::may_change_metadata(context, target) {
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

    /// Change timestamps of the object identified by an open entry.
    pub fn set_times(
        &self,
        user: UserInfo,
        entry: &ResolverEntry<Backend>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        let context = Context::new(user);
        let target = match &entry.handle {
            // A directory handle is walkable by its identity, which renames cannot redirect.
            Handle::Dir(dir) => ResolvedTarget::Dir(
                self.backend
                    .walking_dir_at(dir)
                    .map_err(|_| SetTimesError::Io)?,
            ),
            Handle::File(_) => self.rewalk_open_file(&context, entry)?,
        };
        Self::authorize_set_times(&context, &target, times)?;
        if matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
        ) {
            return Ok(());
        }
        self.backend.set_times(target, times)
    }

    /// The backend accepts a resolved target rather than an open handle, so rewalk a file from
    /// its original resolution base and verify its identity before updating anything.
    ///
    /// XXX: a renamed, unlinked, or replaced open file therefore fails with EIO, and losing
    /// search permission on the walk fails with EACCES, where Linux updates the open inode.
    fn rewalk_open_file(
        &self,
        context: &Context,
        entry: &ResolverEntry<Backend>,
    ) -> Result<ResolvedTarget<'_>, SetTimesError> {
        let map_walk = |error| match error {
            WalkError::Io
            | WalkError::PathError(
                PathError::NoSuchFileOrDirectory | PathError::MissingComponent,
            ) => SetTimesError::Io,
            WalkError::PathError(error) => SetTimesError::PathError(error),
        };
        // Before resolving: the resolved target can hold a backend lock (e.g. the overlay's
        // namespace) that querying the open handle would take again.
        let opened = self
            .backend
            .status(entry.handle.as_ref())
            .map_err(|_| SetTimesError::Io)?;
        let target = self
            .resolve_target(context, &entry.name, None)
            .map_err(map_walk)?;
        let resolved = self
            .backend
            .resolved_status(&target)
            .map_err(|_| SetTimesError::Io)?;
        if (opened.node_info.dev, opened.node_info.ino)
            != (resolved.node_info.dev, resolved.node_info.ino)
        {
            return Err(SetTimesError::Io);
        }
        Ok(target)
    }

    /// Change the permissions of a file.
    pub fn chmod(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let context = Context::new(user);
        let (path, walked) = self
            .resolve_path(&context, anchor, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let target = self
            .resolve_target(&context, &path, walked)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &target) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(target, mode)
    }

    /// Change the owner of a file.
    pub fn chown(
        &self,
        acting_user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = Context::new(acting_user);
        let (path, walked) = self
            .resolve_path(&context, anchor, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let target = self
            .resolve_target(&context, &path, walked)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &target) {
            return Err(ChownError::NotTheOwner);
        }
        self.backend.chown(target, user, group)
    }

    /// Unlink a file.
    pub fn unlink(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
    ) -> Result<(), UnlinkError> {
        let context = Context::new(user);
        let trailing_slash = path.ends_with('/');
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, anchor, path)
                .map_err(|error| match error {
                    WalkError::Io => UnlinkError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(UnlinkError::IsADirectory);
        };
        if matches!(name.as_str(), "." | "..") {
            return Err(UnlinkError::IsADirectory);
        }
        let writable = Self::check_dir_entries_change(
            &context,
            &parent,
            UnlinkError::ReadOnlyFileSystem,
            UnlinkError::NoWritePerms,
        );
        // Linux checks for a read-only mount before looking up the name.
        if matches!(writable, Err(UnlinkError::ReadOnlyFileSystem)) {
            return writable;
        }
        if trailing_slash {
            // Only a directory may be named with a trailing slash, and unlink cannot remove one.
            return Err(
                match self.backend.resolve(parent, &[&name], &|permissions| {
                    Self::check_search_permission(&context, permissions)
                }) {
                    Ok(Resolution::Found(ResolvedTarget::Dir(_))) => UnlinkError::IsADirectory,
                    Ok(Resolution::Found(ResolvedTarget::File(_))) => {
                        PathError::ComponentNotADirectory.into()
                    }
                    Ok(Resolution::MissingFinal { .. }) => PathError::NoSuchFileOrDirectory.into(),
                    Err(error) => match error.error {
                        WalkError::Io => UnlinkError::Io,
                        WalkError::PathError(error) => error.into(),
                    },
                },
            );
        }
        if let Err(error) = writable {
            return Err(
                if matches!(self.name_exists(&context, parent, &name), Ok(false)) {
                    PathError::NoSuchFileOrDirectory.into()
                } else {
                    error
                },
            );
        }
        self.backend.unlink_at(parent, &name)
    }

    /// Create a symbolic link at `linkpath`; `target` is stored verbatim, without resolving it.
    pub fn symlink(
        &self,
        user: UserInfo,
        target: &str,
        anchor: Option<DirAnchor>,
        linkpath: &str,
    ) -> Result<(), SymlinkError> {
        if target.is_empty() {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if target.as_bytes().contains(&0) || linkpath.as_bytes().contains(&0) {
            return Err(PathError::InvalidPathname.into());
        }
        let context = Context::new(user);
        let map_walk_error = |error| match error {
            WalkError::Io => SymlinkError::Io,
            WalkError::PathError(error) => error.into(),
        };
        let Some((parent, name)) = self
            .parent_dir_and_name(&context, anchor.clone(), linkpath)
            .map_err(map_walk_error)?
        else {
            return Err(SymlinkError::AlreadyExists);
        };
        if matches!(name.as_str(), "." | "..") {
            return Err(SymlinkError::AlreadyExists);
        }
        if linkpath.ends_with('/') {
            return Err(
                if self
                    .name_exists(&context, parent, &name)
                    .map_err(map_walk_error)?
                {
                    SymlinkError::AlreadyExists
                } else {
                    PathError::NoSuchFileOrDirectory.into()
                },
            );
        }
        if let Err(error) = Self::check_dir_entries_change(
            &context,
            &parent,
            SymlinkError::ReadOnlyFileSystem,
            SymlinkError::NoWritePerms,
        ) {
            return Err(
                if matches!(self.name_exists(&context, parent, &name), Ok(true)) {
                    SymlinkError::AlreadyExists
                } else {
                    error
                },
            );
        }
        let result = self.backend.symlink_at(
            parent,
            &name,
            target,
            CreationMetadata {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                owner: context.acting_user(),
            },
        );
        // Backends refuse writes without checking the name.
        if let Err(SymlinkError::ReadOnlyFileSystem) = result
            && let Ok(Some((parent, name))) = self.parent_dir_and_name(&context, anchor, linkpath)
            && let Ok(true) = self.name_exists(&context, parent, &name)
        {
            return Err(SymlinkError::AlreadyExists);
        }
        result
    }

    /// Atomically move an entry to a new name, replacing a compatible destination.
    ///
    /// Parent symbolic links are resolved, but final symbolic links are moved themselves.
    /// Each path is resolved from its own anchor.
    pub fn rename(
        &self,
        user: UserInfo,
        old_anchor: Option<DirAnchor>,
        old_path: &str,
        new_anchor: Option<DirAnchor>,
        new_path: &str,
    ) -> Result<(), RenameError> {
        let context = Context::new(user);
        let map_walk_error = |error| match error {
            WalkError::Io => RenameError::Io,
            WalkError::PathError(error) => error.into(),
        };
        let parent = |anchor, path: &str| {
            if path.is_empty() {
                return Err(PathError::NoSuchFileOrDirectory.into());
            }
            if path.contains('\0') {
                return Err(PathError::InvalidPathname.into());
            }
            let Some((parent, name)) = self
                .parent_dir_and_name(&context, anchor, path)
                .map_err(map_walk_error)?
            else {
                return Err(RenameError::Busy);
            };
            if matches!(name.as_str(), "." | "..") {
                return Err(RenameError::Busy);
            }
            let writable = Self::check_dir_entries_change(
                &context,
                &parent,
                RenameError::ReadOnlyFileSystem,
                RenameError::NoWritePerms,
            );
            // Own this directory before walking the other parent: walking handles may retain locks.
            let dir = self
                .backend
                .open_dir(parent, OFlags::PATH)
                .map_err(|error| match error {
                    OpenError::PathError(error) => RenameError::PathError(error),
                    OpenError::ReadOnlyFileSystem => RenameError::ReadOnlyFileSystem,
                    OpenError::NoWritePerms | OpenError::AccessNotAllowed => {
                        RenameError::NoWritePerms
                    }
                    _ => RenameError::Io,
                })?;
            Ok((dir, name, writable))
        };
        let (old_dir, old_name, old_writable) = parent(old_anchor, old_path)?;
        let (new_dir, new_name, new_writable) = parent(new_anchor, new_path)?;
        // Linux checks for a cross-mount rename, then for a read-only mount, before looking up
        // either name. Only the backend knows whether the directories are on different mounts;
        // asking it relies on every backend that sets `on_read_only_fs` (TarRo, ReadOnly,
        // Composer virtual directories) refusing the rename without mutating anything.
        if [&old_writable, &new_writable]
            .into_iter()
            .any(|writable| matches!(writable, Err(RenameError::ReadOnlyFileSystem)))
        {
            return match self
                .backend
                .rename_at(old_dir, &old_name, new_dir, &new_name)
            {
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
            let walking = self
                .backend
                .walking_dir_at(&old_dir)
                .map_err(|_| RenameError::Io)?;
            match self
                .backend
                .resolve(walking, &[&old_name], &|permissions| {
                    Self::check_search_permission(&context, permissions)
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
        self.backend
            .rename_at(old_dir, &old_name, new_dir, &new_name)
    }

    /// Create a new directory.
    pub fn mkdir(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let context = Context::new(user);
        let Some((parent, name)) = self
            .parent_dir_and_name(&context, anchor.clone(), path)
            .map_err(|error| match error {
                WalkError::Io => MkdirError::Io,
                WalkError::PathError(error) => error.into(),
            })?
        else {
            return Err(MkdirError::AlreadyExists);
        };
        if matches!(name.as_str(), "." | "..") {
            return Err(MkdirError::AlreadyExists);
        }
        if let Err(error) = Self::check_dir_entries_change(
            &context,
            &parent,
            MkdirError::ReadOnlyFileSystem,
            MkdirError::NoWritePerms,
        ) {
            return Err(
                if matches!(self.name_exists(&context, parent, &name), Ok(true)) {
                    MkdirError::AlreadyExists
                } else {
                    error
                },
            );
        }
        let result = self
            .backend
            .mkdir_at(
                parent,
                &name,
                CreationMetadata {
                    mode,
                    owner: context.acting_user(),
                },
            )
            .map(|_| ());
        // Backends refuse writes without checking the name.
        if let Err(MkdirError::ReadOnlyFileSystem) = result
            && let Ok(Some((parent, name))) = self.parent_dir_and_name(&context, anchor, path)
            && let Ok(true) = self.name_exists(&context, parent, &name)
        {
            return Err(MkdirError::AlreadyExists);
        }
        result
    }

    /// Remove a directory.
    pub fn rmdir(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
    ) -> Result<(), RmdirError> {
        let context = Context::new(user);
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, anchor, path)
                .map_err(|error| match error {
                    WalkError::Io => RmdirError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(RmdirError::Busy);
        };
        match name.as_str() {
            "." => return Err(PathError::InvalidPathname.into()),
            ".." => return Err(RmdirError::NotEmpty),
            _ => {}
        }
        let writable = Self::check_dir_entries_change(
            &context,
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
                if matches!(self.name_exists(&context, parent, &name), Ok(false)) {
                    PathError::NoSuchFileOrDirectory.into()
                } else {
                    error
                },
            );
        }
        self.backend.rmdir_at(parent, &name)
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names including synthesized `.` and `..` entries.
    pub fn read_dir(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
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
        entries.extend(self.backend.list_dir_at(dir.clone())?);
        Ok(entries)
    }

    /// Obtain the status of a file/directory/... on the file-system.
    ///
    /// If `follow_symlinks` is false, a final symbolic link is described itself.
    pub fn file_status(
        &self,
        user: UserInfo,
        anchor: Option<DirAnchor>,
        path: &str,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, FileStatusError> {
        let context = Context::new(user);
        let (path, walked) = self
            .resolve_path(&context, anchor, path, follow_symlinks, false)
            .map_err(|error| match error {
                WalkError::Io => FileStatusError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let target = self
            .resolve_target(&context, &path, walked)
            .map_err(|error| match error {
                WalkError::Io => FileStatusError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        // Unlike an O_PATH open, this must not trigger backend open hooks.
        self.backend.resolved_status(&target)
    }

    /// Returns the current physical name of a directory (or, where the backend cannot name it,
    /// the name it was opened by), or the name a file was opened by.
    ///
    /// A file opened relative to a directory is named under that directory's current name. An
    /// unlinked directory has no name.
    pub(super) fn handle_path(&self, entry: &ResolverEntry<Backend>) -> Result<String, WalkError> {
        match &entry.handle {
            Handle::Dir(dir) => match self.backend.dir_path(dir)? {
                Some(components) => Ok(ResolvedPath::join(String::new(), &components)),
                None => self.opened_name(entry),
            },
            Handle::File(_) => self.opened_name(entry),
        }
    }

    /// The name an entry was opened by, following renames of the directory it was opened from.
    fn opened_name(&self, entry: &ResolverEntry<Backend>) -> Result<String, WalkError> {
        let Some(anchor) = &entry.name.anchor else {
            return Ok(entry.name.to_absolute());
        };
        match self.backend.dir_path(&anchor.dir) {
            Ok(Some(mut components)) => {
                components.extend(entry.name.components.iter().cloned());
                Ok(ResolvedPath::join(String::new(), &components))
            }
            Ok(None) | Err(WalkError::PathError(PathError::NoSuchFileOrDirectory)) => {
                Ok(entry.name.to_absolute())
            }
            Err(error) => Err(error),
        }
    }

    /// Equivalent to [`Self::file_status`], but on an open entry instead.
    pub fn handle_status(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<super::FileStatus, FileStatusError> {
        self.backend.status(entry.handle.as_ref())
    }

    /// Applies, or fails without blocking, an advisory whole-file lock held by the open
    /// description `owner`.
    ///
    /// Conflicts fail with [`BrokerError::NonBlockingWouldBlock`](crate::BrokerError), since
    /// waiting in the broker could block the request that unlocks.
    pub(super) fn lock(
        &self,
        entry: &ResolverEntry<Backend>,
        owner: Weak<dyn Send + Sync>,
        operation: FileLockOperation,
    ) -> crate::Result<Result<(), FileStatusError>> {
        let request = match operation {
            FileLockOperation::Shared | FileLockOperation::Exclusive => {
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
    pub fn terminal(&self, entry: &ResolverEntry<Backend>) -> Option<Arc<dyn TerminalEndpoint>> {
        match &entry.handle {
            Handle::File(file) if !entry.path_only => match self.backend.terminal(file)? {
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
    pub fn readiness_source(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Option<Arc<dyn ReadinessSource>> {
        if let Some(controlling) = &entry.controlling_terminal {
            return Some(Arc::clone(&controlling.terminal) as Arc<dyn ReadinessSource>);
        }
        match &entry.handle {
            Handle::File(file) if !entry.path_only => self.backend.readiness_source(file),
            Handle::File(_) | Handle::Dir(_) => None,
        }
    }

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., set up via [`super::in_mem::InitialNode::File`]).
    ///
    /// Returns `None` if no static backing data is available/supported.
    pub fn get_static_backing_data(&self, entry: &ResolverEntry<Backend>) -> Option<&'static [u8]> {
        match &entry.handle {
            Handle::File(file) => self.backend.get_static_backing_data(file),
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
        entry: &ResolverEntry<Backend>,
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
        let file = self.backend.map_shared(file)?;
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
pub struct ResolverEntry<Backend: super::backend::Backend> {
    handle: Handle,
    _backend: core::marker::PhantomData<Backend>,
    read_allowed: bool,
    write_allowed: bool,
    position: usize,
    append_mode: bool,
    /// Whether reads and writes that would block fail instead of waiting.
    nonblocking: bool,
    path_only: bool,
    seek_behavior: SeekBehavior,
    /// Symlink-expanded location of the opened object, relative to the directory it was opened
    /// from (or to the root), as resolved when it was opened. Backend operations that need a
    /// path rewalk it; later renames or removals of the object are not reflected.
    name: ResolvedPath,
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

impl<Backend: super::backend::Backend> ResolverEntry<Backend> {
    /// Captures this entry as the starting point of relative lookups.
    #[must_use]
    pub fn anchor(&self) -> DirAnchor {
        DirAnchor(match &self.handle {
            Handle::Dir(dir) => Some(WalkAnchor {
                dir: dir.clone(),
                hint: self.name.to_absolute(),
            }),
            Handle::File(_) => None,
        })
    }

    pub(crate) const fn is_path_only(&self) -> bool {
        self.path_only
    }

    /// Absolute name of the opened object as recorded when it was opened, naming the directory
    /// it was opened from by that directory's recorded name.
    #[cfg(test)]
    pub(crate) fn path(&self) -> String {
        self.name.to_absolute()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::{in_mem::InMem, inode_allocator::InodeAllocators};
    use crate::test_platform::TestPlatform;

    #[test]
    fn directory_paths_follow_identity_across_rename_removal_and_mounts() {
        use crate::fs::composer::Composer;
        let fs = Resolver::<TestPlatform, _>::new(
            Composer::<TestPlatform>::builder()
                .mount("/bridge/fs", InMem::<TestPlatform>::new)
                .mount("/bridge/fs/nested", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        let open = |path| fs.open(user, None, path, OFlags::PATH, mode).unwrap();
        for path in ["/", "/bridge", "/bridge/fs", "/bridge/fs/nested"] {
            assert_eq!(fs.handle_path(&open(path)).unwrap(), path);
        }
        fs.mkdir(user, None, "/bridge/fs/old", mode).unwrap();
        fs.mkdir(user, None, "/bridge/fs/old/child", mode).unwrap();
        let dir = open("/bridge/fs/old/child");
        let anchored = fs
            .open(
                user,
                Some(open("/bridge/fs/old").anchor()),
                "anchored",
                OFlags::CREAT,
                mode,
            )
            .unwrap();
        fs.rename(user, None, "/bridge/fs/old", None, "/bridge/fs/moved")
            .unwrap();
        fs.mkdir(user, None, "/bridge/fs/old", mode).unwrap();
        assert_eq!(fs.handle_path(&dir).unwrap(), "/bridge/fs/moved/child");
        // A file opened relative to a directory is named under the directory's current name.
        assert_eq!(
            fs.handle_path(&anchored).unwrap(),
            "/bridge/fs/moved/anchored"
        );

        fs.rename(
            user,
            None,
            "/bridge/fs/moved/child",
            None,
            "/bridge/fs/promoted",
        )
        .unwrap();
        let nested = fs
            .open(user, Some(dir.anchor()), "../nested", OFlags::PATH, mode)
            .unwrap();
        assert_eq!(
            fs.handle_status(&nested).unwrap().node_info,
            fs.handle_status(&open("/bridge/fs/nested"))
                .unwrap()
                .node_info
        );
        fs.rmdir(user, None, "/bridge/fs/promoted").unwrap();
        fs.mkdir(user, None, "/bridge/fs/promoted", mode).unwrap();
        assert!(matches!(
            fs.handle_path(&dir),
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
    }

    #[test]
    fn directory_covered_by_a_later_mount_is_not_reported_removed() {
        use crate::fs::composer::Composer;
        let fs = Resolver::<TestPlatform, _>::new(
            Composer::<TestPlatform>::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        fs.mkdir(user, None, "/mnt", mode).unwrap();
        fs.mkdir(user, None, "/mnt/dir", mode).unwrap();
        let dir = fs.open(user, None, "/mnt/dir", OFlags::PATH, mode).unwrap();
        fs.mount_in_mem(user, "/mnt").unwrap();
        // The shadowed directory is still linked, so it must not be reported as removed.
        assert_eq!(fs.handle_path(&dir).unwrap(), "/mnt/dir");
    }

    #[test]
    fn unnamed_mounted_parent_still_supports_dotdot() {
        use crate::fs::composer::Composer;
        let fs = Resolver::<TestPlatform, _>::new(
            Composer::<TestPlatform>::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .mount("/nested", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        fs.mkdir(user, None, "/parent", mode).unwrap();
        fs.mkdir(user, None, "/parent/child", mode).unwrap();
        let child = fs
            .open(user, None, "/parent/child", OFlags::PATH, mode)
            .unwrap();
        fs.rmdir(user, None, "/parent/child").unwrap();
        fs.rmdir(user, None, "/parent").unwrap();
        let parent = fs
            .open(user, Some(child.anchor()), "..", OFlags::PATH, mode)
            .unwrap();
        assert!(matches!(
            fs.handle_path(&parent),
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(
            fs.open(user, Some(parent.anchor()), "nested", OFlags::PATH, mode)
                .is_err()
        );
        let nested = fs
            .open(user, Some(parent.anchor()), "../nested", OFlags::PATH, mode)
            .unwrap();
        assert_eq!(fs.handle_path(&nested).unwrap(), "/nested");
    }

    #[test]
    fn set_times_uses_held_directory_after_rename() {
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocators::new().next(),
        ));
        let user = UserInfo::ROOT;
        fs.mkdir(user, None, "/dir", Mode::RWXU).unwrap();
        let dir = fs
            .open(user, None, "/dir", OFlags::PATH, Mode::empty())
            .unwrap();
        let child = fs
            .open(user, Some(dir.anchor()), "child", OFlags::CREAT, Mode::RWXU)
            .unwrap();
        fs.rename(user, None, "/dir", None, "/moved").unwrap();
        fs.mkdir(user, None, "/dir", Mode::RWXU).unwrap();
        let decoy = fs
            .open(user, None, "/dir/child", OFlags::CREAT, Mode::RWXU)
            .unwrap();
        let before = fs.handle_status(&decoy).unwrap().times;
        let mtime = crate::fs::FileTimestamp {
            seconds: 123,
            nanoseconds: 456,
        };
        let change = SetFileTimes {
            access: FileTimeUpdate::Omit,
            modify: FileTimeUpdate::Set(mtime),
        };
        fs.set_times(user, &child, &change).unwrap();
        assert_eq!(
            fs.handle_status(&child).unwrap().times.unwrap().modified,
            mtime
        );
        assert_eq!(fs.handle_status(&decoy).unwrap().times, before);
    }

    #[test]
    fn relative_operations_follow_held_directories_after_rename() {
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocators::new().next(),
        ));
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        let open_dir = |path| {
            fs.open(user, None, path, OFlags::PATH | OFlags::DIRECTORY, mode)
                .unwrap()
        };
        fs.mkdir(user, None, "/old", mode).unwrap();
        fs.mkdir(user, None, "/dst", mode).unwrap();
        let src = open_dir("/old");
        let dst = open_dir("/dst");
        fs.rename(user, None, "/old", None, "/dst/moved").unwrap();
        fs.mkdir(user, None, "/old", mode).unwrap();

        fs.mkdir(user, Some(src.anchor()), "sub", mode).unwrap();
        let file = fs
            .open(user, Some(src.anchor()), "sub/f", OFlags::CREAT, mode)
            .unwrap();
        let ino = fs.handle_status(&file).unwrap().node_info.ino;
        fs.symlink(user, "sub/../sub/f", Some(src.anchor()), "relative")
            .unwrap();
        assert_eq!(
            fs.read_link(user, Some(src.anchor()), "relative").unwrap(),
            "sub/../sub/f"
        );
        fs.symlink(user, "/dst/moved/sub/f", Some(dst.anchor()), "absolute")
            .unwrap();
        for path in ["relative", "../absolute"] {
            assert_eq!(
                fs.file_status(user, Some(src.anchor()), path, true)
                    .unwrap()
                    .node_info
                    .ino,
                ino,
                "wrong inode for {path}"
            );
        }
        fs.chmod(user, Some(src.anchor()), "relative", Mode::RUSR)
            .unwrap();
        fs.chown(user, Some(src.anchor()), "relative", Some(42), None)
            .unwrap();
        fs.rename(
            user,
            Some(src.anchor()),
            "sub/f",
            Some(dst.anchor()),
            "received",
        )
        .unwrap();
        assert_eq!(
            fs.file_status(user, None, "/dst/received", true)
                .unwrap()
                .node_info
                .ino,
            ino
        );
        assert!(fs.file_status(user, None, "/old/sub", true).is_err());
        fs.unlink(user, Some(dst.anchor()), "received").unwrap();
        fs.rmdir(user, Some(src.anchor()), "sub").unwrap();

        assert!(matches!(
            fs.file_status(user, Some(file.anchor()), "child", true),
            Err(FileStatusError::PathError(
                PathError::ComponentNotADirectory
            ))
        ));
        assert!(
            fs.file_status(user, Some(file.anchor()), "/dst", true)
                .is_ok()
        );
        // Search checks apply to held directories as of now, not as of when they were opened.
        let owner = UserInfo {
            user: 1000,
            group: 1000,
        };
        fs.chmod(user, None, "/dst", Mode::RWXU | Mode::XOTH)
            .unwrap();
        fs.chown(
            user,
            None,
            "/dst/moved",
            Some(owner.user),
            Some(owner.group),
        )
        .unwrap();
        fs.chmod(user, None, "/dst/moved", Mode::WUSR).unwrap();
        assert!(matches!(
            fs.open(owner, Some(src.anchor()), "new", OFlags::CREAT, mode),
            Err(OpenError::PathError(PathError::NoSearchPerms))
        ));
        assert!(matches!(
            fs.mkdir(owner, Some(dst.anchor()), "moved/new", mode),
            Err(MkdirError::PathError(PathError::NoSearchPerms))
        ));
        for path in [".", "..", "relative"] {
            assert!(matches!(
                fs.file_status(owner, Some(src.anchor()), path, true),
                Err(FileStatusError::PathError(PathError::NoSearchPerms))
            ));
        }
    }

    #[test]
    fn handles_cross_mounts_added_after_they_were_opened() {
        use crate::fs::composer::Composer;
        let fs = Resolver::<TestPlatform, _>::new(
            Composer::<TestPlatform>::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        fs.mkdir(user, None, "/a", mode).unwrap();
        fs.mkdir(user, None, "/a/b", mode).unwrap();
        fs.mkdir(user, None, "/a/t", mode).unwrap();
        let b = fs.open(user, None, "/a/b", OFlags::PATH, mode).unwrap();
        let a = fs
            .open(user, Some(b.anchor()), "..", OFlags::PATH, mode)
            .unwrap();
        // Both handles now record locations under `/a`.
        fs.rename(user, None, "/a", None, "/z").unwrap();
        fs.mount_in_mem(user, "/z/t").unwrap();
        let created = fs
            .open(user, Some(a.anchor()), "t/x", OFlags::CREAT, mode)
            .unwrap();
        let mounted = fs.open(user, None, "/z/t", OFlags::PATH, mode).unwrap();
        assert_eq!(
            fs.handle_status(&created).unwrap().node_info.dev,
            fs.handle_status(&mounted).unwrap().node_info.dev
        );
        assert!(fs.file_status(user, None, "/z/t/x", true).is_ok());
    }

    #[test]
    fn dotdot_from_a_mount_root_reaches_the_outer_namespace() {
        use crate::fs::composer::Composer;
        let fs = Resolver::<TestPlatform, _>::new(
            Composer::<TestPlatform>::builder()
                .mount("/", InMem::<TestPlatform>::new)
                .mount("/m", InMem::<TestPlatform>::new)
                .build()
                .unwrap(),
        );
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        fs.mkdir(user, None, "/outer", mode).unwrap();
        let m = fs.open(user, None, "/m", OFlags::PATH, mode).unwrap();
        let up = fs
            .open(user, Some(m.anchor()), "..", OFlags::PATH, mode)
            .unwrap();
        assert_eq!(fs.handle_path(&up).unwrap(), "/");
        let outer = fs
            .open(user, Some(m.anchor()), "../outer", OFlags::PATH, mode)
            .unwrap();
        assert_eq!(
            fs.handle_status(&outer).unwrap().node_info,
            fs.file_status(user, None, "/outer", true)
                .unwrap()
                .node_info
        );
        let top = fs
            .open(user, Some(m.anchor()), "../../..", OFlags::PATH, mode)
            .unwrap();
        assert_eq!(fs.handle_path(&top).unwrap(), "/");
    }

    #[test]
    fn removed_directories_accept_no_new_entries() {
        let fs = Resolver::<TestPlatform, _>::new(InMem::<TestPlatform>::new(
            InodeAllocators::new().next(),
        ));
        let user = UserInfo::ROOT;
        let mode = Mode::RWXU;
        fs.mkdir(user, None, "/d", mode).unwrap();
        fs.mkdir(user, None, "/e", mode).unwrap();
        let d = fs
            .open(user, None, "/d", OFlags::RDONLY | OFlags::DIRECTORY, mode)
            .unwrap();
        fs.rmdir(user, None, "/d").unwrap();
        assert!(matches!(
            fs.mkdir(user, Some(d.anchor()), "x", mode),
            Err(MkdirError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(
            fs.open(user, Some(d.anchor()), "x", OFlags::CREAT, mode),
            Err(OpenError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(
            fs.symlink(user, "target", Some(d.anchor()), "x"),
            Err(SymlinkError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(
            fs.rename(user, None, "/e", Some(d.anchor()), "e"),
            Err(RenameError::PathError(PathError::NoSuchFileOrDirectory))
        ));
        assert!(matches!(fs.read_dir(&d), Err(ReadDirError::Removed)));
        assert!(fs.file_status(user, None, "/e", true).is_ok());
    }
}
