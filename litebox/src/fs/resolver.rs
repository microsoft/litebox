// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::UserInfo;
use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError,
    WriteError,
};
use super::{
    FileType, Mode, OFlags,
    backend::{
        DirHandle, Handle, HandleRef, PermissionCheck, PermissionInfo, SeekBehavior, WalkOutcome,
        WalkStopReason, WalkingDirHandle,
    },
};

/// The north-facing filesystem entry point, generic over a [`Backend`](super::backend::Backend).
// NOTE(jayb): the `Context` separation is in preparation for multi-process support; specifically,
// each guest process would have their own `Context` but would share the resolver. Currently, since
// we are using the `FileSystem` trait for migration, the interfaces do not show the full actual
// separated context support (yet!). Nonetheless, future changes will separate this out.
pub struct Resolver<
    Platform: sync::RawSyncPrimitivesProvider,
    Backend: super::backend::Backend + 'static,
> {
    litebox: LiteBox<Platform>,
    backend: Backend,
    /// Stand-in for the per-caller context, until callers own their own. See the note above.
    migration_context: Context,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a new resolver over a `backend`.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, backend: Backend) -> Self {
        Self {
            litebox: litebox.clone(),
            backend,
            migration_context: Context::new(),
        }
    }

    /// Set the acting user for all subsequent operations, returning the previous one.
    ///
    /// Non-test callers set up whatever needs a different user while constructing the backend;
    /// this exists so that the tests can exercise operations that depend on the acting user.
    ///
    /// TODO(jayb): transitionary `pub(super)` accessor; this should go away once callers own their
    /// own [`Context`], at which point they can set the acting user directly.
    #[cfg(test)]
    pub(super) fn swap_acting_user(&mut self, user: UserInfo) -> UserInfo {
        core::mem::replace(&mut self.migration_context.user_info, user)
    }

    /// Direct access to the backend, so that the tests can reach backend-owned state (namely its
    /// own copy of the acting user).
    ///
    /// TODO(jayb): transitionary `pub(super)` accessor; this should go away along with the
    /// backend's copy of the acting user.
    #[cfg(test)]
    pub(super) fn backend_mut(&mut self) -> &mut Backend {
        &mut self.backend
    }
}

/// Per-call resolution context.  The user may hold and mutate this as they wish.
#[derive(Clone, Debug)]
pub struct Context {
    /// Current working directory.
    ///
    /// An empty list is equivalent to `/`. Guaranteed to never have `.` or `..`.
    cwd: Vec<String>,
    /// Effective user for permission checks.
    user_info: UserInfo,
}

impl Context {
    /// A new default context, anchored at `/` for a non-root user.
    pub fn new() -> Context {
        Self {
            cwd: vec![],
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Resolve `path` against the current context.
    // XXX(jayb): if/when we support chroot, we might need to tweak this to not allow "escaping"
    // outside the chrooted part.
    // XXX(jayb): since we are migrating all resolution into the resolver, we probably don't need
    // `Arg` anymore, so could get rid of it in the future.
    fn resolve(&self, path: impl Arg) -> Result<ResolvedPath, PathError> {
        let mut components = if path.as_rust_str()?.starts_with('/') {
            vec![]
        } else {
            self.cwd.clone()
        };
        for component in path.components()? {
            match component {
                "" | "." => {}
                ".." => {
                    let _ = components.pop();
                }
                _ => {
                    components.push(component.into());
                }
            }
        }
        Ok(ResolvedPath { components })
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

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Absolute normalized path, must only be created from [`Context::resolve`].
struct ResolvedPath {
    components: Vec<String>,
}

impl ResolvedPath {
    fn parent_and_name(&self) -> Option<(Vec<&str>, &str)> {
        let (name, parent) = self.components.split_last()?;
        Some((parent.iter().map(String::as_str).collect(), name.as_str()))
    }
}

/// A directory reached by a walk, plus the permission metadata to check against it.
struct WalkedDir<'a> {
    handle: WalkingDirHandle<'a>,
    /// `None` when the walk ended at the backend root, which reports no permission metadata.
    permissions: Option<PermissionCheck>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::private::Sealed for Resolver<Platform, Backend>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    fn parent_dir_and_name<'a>(
        &self,
        context: &Context,
        path: &'a ResolvedPath,
    ) -> Result<Option<(WalkedDir<'_>, &'a str)>, WalkError> {
        // Return the walking handle rather than an owned directory handle so backends can keep any
        // locks acquired during path resolution held across the final operation. This lets e.g.
        // "walk parent + mutate child" stay atomic.
        let Some((parent_components, name)) = path.parent_and_name() else {
            return Ok(None);
        };
        let parent = self.walk_to_directory(
            context,
            self.backend.root(),
            &parent_components,
            #[cfg(debug_assertions)]
            &parent_components,
        )?;
        Ok(Some((parent, name)))
    }

    /// Whether `context` may add or remove entries in `dir`.
    ///
    /// A `dir` without permission metadata is the backend root, which the backend does not report
    /// permissions for; such directories are currently left unchecked.
    // TODO(jayb): Check write permission on the root directory too. That needs the backend to
    // report permissions for [`super::backend::Backend::root`].
    // TODO(jayb): Prioritize `EROFS` before this permission check runs; currently not an issue due
    // to 0777 from read-only backends, but needs an update then.
    fn can_change_entries_in_dir(context: &Context, dir: &WalkedDir<'_>) -> bool {
        match &dir.permissions {
            None | Some(PermissionCheck::ByBackend) => true,
            Some(PermissionCheck::ByResolver(permissions)) => context.can_write(permissions),
        }
    }

    fn owned_parent_dir(&self, dir: WalkingDirHandle<'_>) -> Result<DirHandle, WalkError> {
        self.backend
            .owned_dir_at(dir, OFlags::PATH)
            .map_err(|error| match error {
                OpenError::PathError(PathError::NoSuchFileOrDirectory) => {
                    PathError::MissingComponent.into()
                }
                OpenError::PathError(error) => error.into(),
                _ => WalkError::Io,
            })
    }

    /// Resolve `path` to an owned handle on the file or directory it names.
    ///
    /// The handle is taken with [`OFlags::PATH`], as it addresses the object for operations that
    /// do not read or write its contents, and thus needs no access permissions on it.
    fn path_handle(&self, context: &Context, path: &ResolvedPath) -> Result<Handle, WalkError> {
        let map_open_error = |error| match error {
            OpenError::PathError(error) => WalkError::PathError(error),
            _ => WalkError::Io,
        };
        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        if components.is_empty() {
            let root = self
                .backend
                .owned_dir_at(self.backend.root(), OFlags::PATH)
                .map_err(map_open_error)?;
            return Ok(Handle::Dir(root));
        }
        let (outcome, walked) = self.walk_path(
            context,
            self.backend.root(),
            &components,
            #[cfg(debug_assertions)]
            &components,
        )?;
        match outcome.stop_reason {
            WalkStopReason::CompleteDirectory => Ok(Handle::Dir(
                self.backend
                    .owned_dir_at(outcome.last, OFlags::PATH)
                    .map_err(map_open_error)?,
            )),
            WalkStopReason::StoppedAtNonDirectory => Ok(Handle::File(
                self.backend
                    .open_file_at(outcome.last, components[walked], OFlags::PATH)
                    .map_err(map_open_error)?
                    .item,
            )),
            WalkStopReason::Continue => {
                // `walk_path` validates stop reasons before returning.
                unreachable!()
            }
        }
    }

    fn walk_to_directory<'a>(
        &'a self,
        context: &Context,
        from: WalkingDirHandle<'a>,
        components: &[&str],
        #[cfg(debug_assertions)] absolute_components: &[&str],
    ) -> Result<WalkedDir<'a>, WalkError> {
        if components.is_empty() {
            // TODO(jayb): Decide whether empty walks from a non-root handle need permission checks.
            return Ok(WalkedDir {
                handle: from,
                permissions: None,
            });
        }

        let outcome =
            self.backend
                .walk_directories(from, components)
                .map_err(|error| match error {
                    WalkError::PathError(PathError::NoSuchFileOrDirectory) => {
                        PathError::MissingComponent.into()
                    }
                    error => error,
                })?;
        Self::check_walk_permissions(
            context,
            #[cfg(debug_assertions)]
            absolute_components,
            &outcome,
        )?;

        match outcome.stop_reason {
            WalkStopReason::CompleteDirectory => {
                assert_eq!(outcome.components.len(), components.len());
                let permissions = outcome
                    .components
                    .last()
                    .map(|component| component.permissions.clone());
                Ok(WalkedDir {
                    handle: outcome.last,
                    permissions,
                })
            }
            WalkStopReason::StoppedAtNonDirectory => {
                Err(WalkError::PathError(PathError::ComponentNotADirectory))
            }
            WalkStopReason::Continue => {
                // TODO(jayb): Continue walking from `outcome.last` once partial backend walks are
                // supported by the resolver.
                unimplemented!("partial backend walks are not supported yet")
            }
        }
    }

    fn walk_path<'a>(
        &'a self,
        context: &Context,
        from: WalkingDirHandle<'a>,
        components: &[&str],
        #[cfg(debug_assertions)] absolute_components: &[&str],
    ) -> Result<(WalkOutcome<WalkingDirHandle<'a>>, usize), WalkError> {
        assert!(!components.is_empty());
        let outcome = self.backend.walk_directories(from, components)?;
        Self::check_walk_permissions(
            context,
            #[cfg(debug_assertions)]
            absolute_components,
            &outcome,
        )?;

        let walked = outcome.components.len();
        match outcome.stop_reason {
            WalkStopReason::CompleteDirectory => {
                assert_eq!(walked, components.len());
                Ok((outcome, walked))
            }
            WalkStopReason::StoppedAtNonDirectory if walked + 1 == components.len() => {
                Ok((outcome, walked))
            }
            WalkStopReason::StoppedAtNonDirectory => {
                Err(WalkError::PathError(PathError::ComponentNotADirectory))
            }
            WalkStopReason::Continue => {
                // TODO(jayb): Continue walking from `outcome.last` once partial backend walks are
                // supported by the resolver.
                unimplemented!("partial backend walks are not supported yet")
            }
        }
    }

    fn check_walk_permissions(
        context: &Context,
        #[cfg(debug_assertions)] absolute_components: &[&str],
        outcome: &WalkOutcome<WalkingDirHandle<'_>>,
    ) -> Result<(), PathError> {
        for (idx, walked) in outcome.components.iter().enumerate() {
            match &walked.permissions {
                PermissionCheck::ByBackend => {}
                PermissionCheck::ByResolver(permissions) => {
                    if !context.can_execute(permissions) {
                        return Err(PathError::NoSearchPerms {
                            #[cfg(debug_assertions)]
                            dir: {
                                let mut path = String::new();
                                for component in &absolute_components[..=idx] {
                                    path.push('/');
                                    path.push_str(component);
                                }
                                path
                            },
                            #[cfg(debug_assertions)]
                            perms: permissions.mode,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

// NOTE(jayb): purely as a migration feature, until we have completely separated contexts. See
// comment on [`Resolver`].
impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    fn context_pre_context_management_changes(&self) -> &Context {
        &self.migration_context
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::FileSystem for Resolver<Platform, Backend>
{
    fn open(&self, path: impl Arg, flags: OFlags, mode: Mode) -> Result<TypedFd<Self>, OpenError> {
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

        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let insert = |handle, seek_behavior| {
            self.litebox.descriptor_table_mut().insert(ResolverEntry {
                handle,
                _backend: core::marker::PhantomData,
                read_allowed,
                write_allowed,
                position: 0,
                append_mode,
                path_only,
                seek_behavior,
            })
        };

        if path.components.is_empty() {
            if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                return Err(OpenError::AlreadyExists);
            }
            return Ok(insert(
                Handle::Dir(self.backend.owned_dir_at(self.backend.root(), flags)?),
                SeekBehavior::NonSeekable,
            ));
        }

        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        let walk = self.walk_path(
            context,
            self.backend.root(),
            &components,
            #[cfg(debug_assertions)]
            &components,
        );
        match walk {
            Ok((outcome, _)) if outcome.stop_reason == WalkStopReason::CompleteDirectory => {
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                Ok(insert(
                    Handle::Dir(self.backend.owned_dir_at(outcome.last, flags)?),
                    SeekBehavior::NonSeekable,
                ))
            }
            Ok((outcome, walked))
                if outcome.stop_reason == WalkStopReason::StoppedAtNonDirectory =>
            {
                let name = components[walked];
                // TODO(jayb): Reject O_CREAT | O_EXCL before invoking the backend, so open-time
                // side effects like truncation cannot happen before AlreadyExists is returned.
                let file = self.backend.open_file_at(outcome.last, name, flags)?;
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                if !path_only
                    && let PermissionCheck::ByResolver(permissions) = &file.permissions
                    && ((read_allowed && !context.can_read(permissions))
                        || (write_allowed && !context.can_write(permissions)))
                {
                    return Err(OpenError::AccessNotAllowed);
                }
                let seek_behavior = self.backend.seek_behavior(&file.item);
                Ok(insert(Handle::File(file.item), seek_behavior))
            }
            Ok(_) => {
                // `walk_path` validates stop reasons before returning.
                unreachable!()
            }
            Err(WalkError::PathError(PathError::NoSuchFileOrDirectory))
                if flags.contains(OFlags::CREAT) =>
            {
                let Some((parent_components, name)) = path.parent_and_name() else {
                    unreachable!("root path was handled above")
                };
                let parent = self
                    .walk_to_directory(
                        context,
                        self.backend.root(),
                        &parent_components,
                        #[cfg(debug_assertions)]
                        &parent_components,
                    )
                    .map_err(|error| match error {
                        WalkError::Io => OpenError::Io,
                        WalkError::PathError(error) => error.into(),
                    })?;
                if !Self::can_change_entries_in_dir(context, &parent) {
                    return Err(OpenError::NoWritePerms);
                }
                let parent = self
                    .owned_parent_dir(parent.handle)
                    .map_err(|error| match error {
                        WalkError::Io => OpenError::Io,
                        WalkError::PathError(error) => error.into(),
                    })?;
                let file = self.backend.create_file_at(parent, name, mode)?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(insert(Handle::File(file), seek_behavior))
            }
            Err(error) => match error {
                WalkError::Io => Err(OpenError::Io),
                WalkError::PathError(error) => Err(error.into()),
            },
        }
    }

    fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        self.litebox.descriptor_table_mut().remove(fd);
        Ok(())
    }

    fn read(
        &self,
        fd: &TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        // XXX(jayb): This over-holds the descriptor-entry lock across backend I/O. We need a
        // smaller per-open-file-description primitive for position/append serialization, so the
        // descriptor entry can be unlocked before potentially blocking backend calls.
        let file = match &entry.entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(ReadError::NotAFile),
        };
        let seek_behavior = entry.entry.seek_behavior;
        if !entry.entry.read_allowed {
            return Err(ReadError::NotForReading);
        }
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("read from O_PATH fd")
        }

        let read_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased => offset.unwrap_or(entry.entry.position),
        };
        let read = self.backend.read(file, buf, read_offset)?;
        if matches!(seek_behavior, SeekBehavior::PositionBased) && offset.is_none() {
            entry.entry.position = read_offset.checked_add(read).unwrap();
        }
        Ok(read)
    }

    fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(WriteError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        // XXX(jayb): This over-holds the descriptor-entry lock across backend I/O. We need a
        // smaller per-open-file-description primitive for position/append serialization, so the
        // descriptor entry can be unlocked before potentially blocking backend calls.
        let file = match &entry.entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(WriteError::NotAFile),
        };
        let seek_behavior = entry.entry.seek_behavior;
        if !entry.entry.write_allowed {
            return Err(WriteError::NotForWriting);
        }
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("write to O_PATH fd")
        }

        let write_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased if entry.entry.append_mode && offset.is_none() => {
                self.backend
                    .status(HandleRef::File(file))
                    .map_err(|_| WriteError::Io)?
                    .size
            }
            SeekBehavior::PositionBased => offset.unwrap_or(entry.entry.position),
        };
        let written = self.backend.write(file, buf, write_offset)?;
        if matches!(seek_behavior, SeekBehavior::PositionBased) && offset.is_none() {
            entry.entry.position = write_offset.checked_add(written).unwrap();
        }
        Ok(written)
    }

    fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(SeekError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        let file = match &entry.entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(SeekError::NotAFile),
        };
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("seek on O_PATH fd")
        }

        match entry.entry.seek_behavior {
            SeekBehavior::NonSeekable => Err(SeekError::NonSeekable),
            SeekBehavior::ZeroPosition => Ok(0),
            SeekBehavior::PositionBased => {
                let file_len = self
                    .backend
                    .status(HandleRef::File(file))
                    .map_err(|_| SeekError::Io)?
                    .size;
                let base = match whence {
                    super::SeekWhence::RelativeToBeginning => 0,
                    super::SeekWhence::RelativeToCurrentOffset => entry.entry.position,
                    super::SeekWhence::RelativeToEnd => file_len,
                };
                let new_position = base
                    .checked_add_signed(offset)
                    .ok_or(SeekError::InvalidOffset)?;
                // TODO(jayb): Linux allows regular files to seek past EOF, while some backends or
                // file types may not. Model that distinction instead of using one resolver rule.
                if new_position > file_len {
                    return Err(SeekError::InvalidOffset);
                }
                entry.entry.position = new_position;
                Ok(new_position)
            }
        }
    }

    fn truncate(
        &self,
        fd: &TypedFd<Self>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(TruncateError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        let file = match &entry.entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(TruncateError::IsDirectory),
        };
        if !entry.entry.write_allowed {
            return Err(TruncateError::NotForWriting);
        }
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("truncate O_PATH fd")
        }

        self.backend.truncate(file, length)?;
        if reset_offset {
            entry.entry.position = 0;
        }
        Ok(())
    }

    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let handle = self
            .path_handle(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.chmod(handle.as_ref(), mode)
    }

    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let handle = self
            .path_handle(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.chown(handle.as_ref(), user, group)
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(context, &path)
                .map_err(|error| match error {
                    WalkError::Io => UnlinkError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(UnlinkError::IsADirectory);
        };
        if !Self::can_change_entries_in_dir(context, &parent) {
            return Err(UnlinkError::NoWritePerms);
        }
        let parent = self
            .owned_parent_dir(parent.handle)
            .map_err(|error| match error {
                WalkError::Io => UnlinkError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.unlink_at(parent, name)
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(context, &path)
                .map_err(|error| match error {
                    WalkError::Io => MkdirError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(MkdirError::AlreadyExists);
        };
        if !Self::can_change_entries_in_dir(context, &parent) {
            return Err(MkdirError::NoWritePerms);
        }
        let parent = self
            .owned_parent_dir(parent.handle)
            .map_err(|error| match error {
                WalkError::Io => MkdirError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.mkdir_at(parent, name, mode).map(|_| ())
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        let context = self.context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(context, &path)
                .map_err(|error| match error {
                    WalkError::Io => RmdirError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(RmdirError::Busy);
        };
        if !Self::can_change_entries_in_dir(context, &parent) {
            return Err(RmdirError::NoWritePerms);
        }
        let parent = self
            .owned_parent_dir(parent.handle)
            .map_err(|error| match error {
                WalkError::Io => RmdirError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.rmdir_at(parent, name)
    }

    fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        let entry = entry.get_entry();
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("read_dir on O_PATH fd")
        }
        let dir = match &entry.entry.handle {
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

    fn file_status(&self, path: impl Arg) -> Result<super::FileStatus, FileStatusError> {
        let fd = self
            .open(path, OFlags::PATH, Mode::empty())
            .map_err(|error| match error {
                OpenError::PathError(error) => error.into(),
                OpenError::Io
                | OpenError::AccessNotAllowed
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::TruncateError(_) => FileStatusError::Io,
            })?;
        let status = self.fd_file_status(&fd);
        self.close(&fd).unwrap();
        status
    }

    fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<super::FileStatus, FileStatusError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(FileStatusError::ClosedFd)?;
        let entry = entry.get_entry();
        self.backend.status(entry.entry.handle.as_ref())
    }

    fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        let entry = self.litebox.descriptor_table().entry_handle(fd)?;
        let entry = entry.get_entry();
        match &entry.entry.handle {
            Handle::File(file) => self.backend.get_static_backing_data(file),
            Handle::Dir(_) => None,
        }
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "resolver fd entries carry independent descriptor flags"
)]
struct ResolverEntry<Backend: super::backend::Backend> {
    handle: Handle,
    _backend: core::marker::PhantomData<Backend>,
    read_allowed: bool,
    write_allowed: bool,
    position: usize,
    append_mode: bool,
    path_only: bool,
    seek_behavior: SeekBehavior,
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider }, Backend: { super::backend::Backend + 'static };
    Resolver<Platform, Backend>;
    @ Backend: { super::backend::Backend + 'static };
    ResolverEntry<Backend>;
    -> ResolverFd<Platform, Backend>;
}
