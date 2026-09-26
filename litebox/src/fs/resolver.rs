// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::{AccessCredentials, DacAccessKind, UserInfo};
use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, ReadlinkError, RmdirError, SeekError, TruncateError, UnlinkError,
    UtimeError, WalkError, WriteError,
};
use super::{
    FileType, Mode, OFlags, Timestamp,
    backend::{
        DirHandle, FileHandle, PermissionCheck, PermissionInfo, SeekBehavior, WalkOutcome,
        WalkStopReason, WalkingDirHandle,
    },
};

/// The north-facing filesystem entry point, generic over a [`Backend`](super::backend::Backend).
///
/// The resolver _itself_ maintains no state; all state is maintained either by the backend or the
/// [`Context`]. The user may choose to store the [`Context`] as they wish.
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
    user_info: UserInfo,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a new resolver over a `backend` for the default 1000/1000 identity.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, backend: Backend) -> Self {
        Self::new_with_user(
            litebox,
            backend,
            UserInfo {
                user: 1000,
                group: 1000,
            },
        )
    }

    /// Construct a new resolver over a `backend` for `user_info`.
    #[must_use]
    pub fn new_with_user(
        litebox: &LiteBox<Platform>,
        backend: Backend,
        user_info: UserInfo,
    ) -> Self {
        Self {
            litebox: litebox.clone(),
            backend,
            user_info,
        }
    }

    #[allow(
        clippy::unused_self,
        reason = "instance method for API symmetry with other *_as helpers"
    )]
    fn context_as<'a>(&self, credentials: AccessCredentials<'a>) -> Context<'a> {
        Context {
            cwd: vec![],
            credentials,
        }
    }
}

/// Per-call resolution context.  The user may hold and mutate this as they wish.
#[derive(Clone, Debug)]
pub struct Context<'a> {
    /// Current working directory.
    ///
    /// An empty list is equivalent to `/`. Guaranteed to never have `.` or `..`.
    cwd: Vec<String>,
    /// Effective user for permission checks.
    credentials: AccessCredentials<'a>,
}

impl Context<'static> {
    /// A new default context, anchored at `/` for a non-root user.
    pub fn new() -> Context<'static> {
        Self {
            cwd: vec![],
            credentials: AccessCredentials::new(1000, 1000, &[]),
        }
    }
}

impl Context<'_> {
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

    fn can_use_noatime(&self, permissions: &PermissionInfo) -> bool {
        self.credentials.user() == 0 || self.credentials.owns(permissions.owner)
    }
}

impl Default for Context<'static> {
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::private::Sealed for Resolver<Platform, Backend>
{
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    fn parent_dir_and_name<'a>(
        &self,
        context: &Context<'_>,
        path: &'a ResolvedPath,
    ) -> Result<Option<(WalkingDirHandle<'_>, &'a str)>, WalkError> {
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

    fn walk_to_directory<'a>(
        &'a self,
        context: &Context<'_>,
        from: WalkingDirHandle<'a>,
        components: &[&str],
        #[cfg(debug_assertions)] absolute_components: &[&str],
    ) -> Result<WalkingDirHandle<'a>, WalkError> {
        if components.is_empty() {
            // TODO(jayb): Decide whether empty walks from a non-root handle need permission checks.
            return Ok(from);
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
            outcome.components.len(),
        )?;

        match outcome.stop_reason {
            WalkStopReason::CompleteDirectory => {
                assert_eq!(outcome.components.len(), components.len());
                Ok(outcome.last)
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
        context: &Context<'_>,
        from: WalkingDirHandle<'a>,
        components: &[&str],
        skip_terminal_directory_permission: bool,
        #[cfg(debug_assertions)] absolute_components: &[&str],
    ) -> Result<(WalkOutcome<WalkingDirHandle<'a>>, usize), WalkError> {
        assert!(!components.is_empty());
        let outcome = self.backend.walk_directories(from, components)?;
        let checked_components = if skip_terminal_directory_permission
            && outcome.stop_reason == WalkStopReason::CompleteDirectory
        {
            outcome.components.len().saturating_sub(1)
        } else {
            outcome.components.len()
        };
        Self::check_walk_permissions(
            context,
            #[cfg(debug_assertions)]
            absolute_components,
            &outcome,
            checked_components,
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
        context: &Context<'_>,
        #[cfg(debug_assertions)] absolute_components: &[&str],
        outcome: &WalkOutcome<WalkingDirHandle<'_>>,
        checked_components: usize,
    ) -> Result<(), PathError> {
        for (idx, walked) in outcome
            .components
            .iter()
            .take(checked_components)
            .enumerate()
        {
            #[cfg(not(debug_assertions))]
            let _ = idx;
            match &walked.permissions {
                PermissionCheck::ByBackend => {}
                PermissionCheck::ByResolver(permissions) => {
                    if !super::dac_allows_as(
                        context.credentials,
                        permissions.owner,
                        permissions.mode,
                        DacAccessKind::DirectorySearch,
                    ) {
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    super::FileSystem for Resolver<Platform, Backend>
{
    fn open(&self, path: impl Arg, flags: OFlags, mode: Mode) -> Result<TypedFd<Self>, OpenError> {
        self.open_as(self.user_info.into(), path, flags, mode)
    }

    fn open_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<Self>, OpenError> {
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
            .union(OFlags::NOATIME)
            .union(OFlags::NOFOLLOW)
            .union(OFlags::APPEND)
            .union(OFlags::PATH);

        let flags = flags.normalized_for_open();
        if flags.intersects(CURRENTLY_SUPPORTED_OFLAGS.complement()) {
            return Err(OpenError::UnsupportedFlags);
        }
        let path_only = flags.contains(OFlags::PATH);

        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed =
            !path_only && (access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR);
        let write_allowed =
            !path_only && (access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR);
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
                OwnedHandle::Dir(self.backend.owned_dir_at(self.backend.root(), flags)?),
                SeekBehavior::NonSeekable,
            ));
        }

        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        let walk = self.walk_path(
            &context,
            self.backend.root(),
            &components,
            path_only,
            #[cfg(debug_assertions)]
            &components,
        );
        match walk {
            Ok((outcome, _)) if outcome.stop_reason == WalkStopReason::CompleteDirectory => {
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                Ok(insert(
                    OwnedHandle::Dir(self.backend.owned_dir_at(outcome.last, flags)?),
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
                    && flags.contains(OFlags::NOATIME)
                    && let PermissionCheck::ByResolver(permissions) = &file.permissions
                    && !context.can_use_noatime(permissions)
                {
                    return Err(OpenError::OperationNotPermitted);
                }
                if !path_only
                    && let PermissionCheck::ByResolver(permissions) = &file.permissions
                    && ((read_allowed
                        && !super::dac_allows_as(
                            context.credentials,
                            permissions.owner,
                            permissions.mode,
                            DacAccessKind::Read,
                        ))
                        || (write_allowed
                            && !super::dac_allows_as(
                                context.credentials,
                                permissions.owner,
                                permissions.mode,
                                DacAccessKind::Write,
                            )))
                {
                    return Err(OpenError::AccessNotAllowed);
                }
                let seek_behavior = self.backend.seek_behavior(&file.item);
                Ok(insert(OwnedHandle::File(file.item), seek_behavior))
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
                        &context,
                        self.backend.root(),
                        &parent_components,
                        #[cfg(debug_assertions)]
                        &parent_components,
                    )
                    .map_err(|error| match error {
                        WalkError::Io => OpenError::Io,
                        WalkError::PathError(error) => error.into(),
                    })?;
                let parent = self.owned_parent_dir(parent).map_err(|error| match error {
                    WalkError::Io => OpenError::Io,
                    WalkError::PathError(error) => error.into(),
                })?;
                let file = self.backend.create_file_at(parent, name, mode)?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(insert(OwnedHandle::File(file), seek_behavior))
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
        if !entry.entry.read_allowed {
            return Err(ReadError::NotForReading);
        }
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(ReadError::NotAFile),
        };
        let seek_behavior = entry.entry.seek_behavior;

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
        if !entry.entry.write_allowed {
            return Err(WriteError::NotForWriting);
        }
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(WriteError::NotAFile),
        };
        let seek_behavior = entry.entry.seek_behavior;

        let write_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased if entry.entry.append_mode && offset.is_none() => {
                self.backend
                    .file_status(file)
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
        if entry.entry.path_only {
            return Err(SeekError::NotAFile);
        }
        if matches!(&entry.entry.handle, OwnedHandle::Dir(_)) {
            let base = match whence {
                super::SeekWhence::RelativeToBeginning => 0,
                super::SeekWhence::RelativeToCurrentOffset => entry.entry.position,
                super::SeekWhence::RelativeToEnd => return Err(SeekError::InvalidOffset),
            };
            let new_position = base
                .checked_add_signed(offset)
                .ok_or(SeekError::InvalidOffset)?;
            if isize::try_from(new_position).is_err() {
                return Err(SeekError::InvalidOffset);
            }
            entry.entry.position = new_position;
            return Ok(new_position);
        }
        let OwnedHandle::File(file) = &entry.entry.handle else {
            unreachable!()
        };

        match entry.entry.seek_behavior {
            SeekBehavior::NonSeekable => Err(SeekError::NonSeekable),
            SeekBehavior::ZeroPosition => Ok(0),
            SeekBehavior::PositionBased => {
                let file_len = self
                    .backend
                    .file_status(file)
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
                if isize::try_from(new_position).is_err() {
                    return Err(SeekError::InvalidOffset);
                }
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
        if entry.entry.path_only {
            return Err(TruncateError::PathOnlyFd);
        }
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(TruncateError::IsDirectory),
        };
        if !entry.entry.write_allowed {
            return Err(TruncateError::NotForWriting);
        }

        self.backend.truncate(file, length)?;
        if reset_offset {
            entry.entry.position = 0;
        }
        Ok(())
    }

    fn chmod(&self, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        self.chmod_as(self.user_info.into(), path, mode)
    }

    fn chmod_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => ChmodError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            // TODO(jayb): Add backend support for mutating the root directory itself.
            unimplemented!("chmod root directory")
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
            WalkError::Io => ChmodError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.backend.chmod_at(parent, name, mode)
    }

    fn fd_chmod(&self, fd: &TypedFd<Self>, mode: Mode) -> Result<(), ChmodError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ChmodError::ClosedFd)?;
        let entry = entry.get_entry();
        if entry.entry.path_only {
            return Err(ChmodError::PathOnlyFd);
        }
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.chmod_file(file, mode),
            OwnedHandle::Dir(dir) => self.backend.chmod_dir(dir, mode),
        }
    }

    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.chown_as(self.user_info.into(), path, user, group)
    }

    fn chown_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => ChownError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            // TODO(jayb): Add backend support for mutating the root directory itself.
            unimplemented!("chown root directory")
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
            WalkError::Io => ChownError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.backend.chown_at(parent, name, user, group)
    }

    fn fd_chown(
        &self,
        fd: &TypedFd<Self>,
        _user: Option<u16>,
        _group: Option<u16>,
    ) -> Result<(), ChownError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ChownError::ClosedFd)?;
        let entry = entry.get_entry();
        if entry.entry.path_only {
            return Err(ChownError::PathOnlyFd);
        }
        // The resolver's backends do not support changing ownership through an open handle
        // (there is no `chown`-by-handle in the `Backend` trait, only the path-based
        // `chown_at`). In the layered stack a writable file is migrated to the upper layer
        // before it is chowned, so the resolver only ever holds read-only descriptors here.
        Err(ChownError::ReadOnlyFileSystem)
    }

    fn utimensat(
        &self,
        path: impl Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        self.utimensat_as(self.user_info.into(), path, atime, mtime)
    }

    fn utimensat_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => UtimeError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            // TODO(jayb): Add backend support for mutating the root directory itself.
            unimplemented!("utimensat root directory")
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
            WalkError::Io => UtimeError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.backend.utimensat_at(parent, name, atime, mtime)
    }

    fn fd_utimensat(
        &self,
        fd: &TypedFd<Self>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
    ) -> Result<(), UtimeError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(UtimeError::ClosedFd)?;
        let entry = entry.get_entry();
        if entry.entry.path_only {
            return Err(UtimeError::PathOnlyFd);
        }
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.utimensat_file(file, atime, mtime),
            OwnedHandle::Dir(dir) => self.backend.utimensat_dir(dir, atime, mtime),
        }
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        self.unlink_as(self.user_info.into(), path)
    }

    fn unlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
    ) -> Result<(), UnlinkError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => UnlinkError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(UnlinkError::IsADirectory);
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
            WalkError::Io => UnlinkError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.backend.unlink_at(parent, name)
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        self.mkdir_as(self.user_info.into(), path, mode)
    }

    fn mkdir_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => MkdirError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(MkdirError::AlreadyExists);
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
            WalkError::Io => MkdirError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.backend.mkdir_at(parent, name, mode).map(|_| ())
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        self.rmdir_as(self.user_info.into(), path)
    }

    fn rmdir_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
    ) -> Result<(), RmdirError> {
        let context = self.context_as(credentials);
        let path = context.resolve(path)?;
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, &path)
                .map_err(|error| match error {
                    WalkError::Io => RmdirError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(RmdirError::Busy);
        };
        let parent = self.owned_parent_dir(parent).map_err(|error| match error {
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
            return Err(ReadDirError::PathOnlyFd);
        }
        let dir = match &entry.entry.handle {
            OwnedHandle::File(_) => return Err(ReadDirError::NotADirectory),
            OwnedHandle::Dir(dir) => dir,
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

    fn with_dir_position<T>(
        &self,
        fd: &TypedFd<Self>,
        f: impl FnOnce(&mut usize) -> T,
    ) -> Result<T, ReadDirError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        if entry.entry.path_only {
            return Err(ReadDirError::PathOnlyFd);
        }
        if !matches!(&entry.entry.handle, OwnedHandle::Dir(_)) {
            return Err(ReadDirError::NotADirectory);
        }
        Ok(f(&mut entry.entry.position))
    }

    fn file_status(&self, path: impl Arg) -> Result<super::FileStatus, FileStatusError> {
        self.file_status_as(self.user_info.into(), path)
    }

    fn file_status_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        let fd = self
            .open_as(credentials, path, OFlags::PATH, Mode::empty())
            .map_err(|error| match error {
                OpenError::PathError(error) => error.into(),
                OpenError::Io
                | OpenError::AccessNotAllowed
                | OpenError::OperationNotPermitted
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::TooManySymbolicLinks
                | OpenError::TruncateError(_)
                // Called above with OFlags::PATH only, always within Resolver::open's
                // supported set.
                | OpenError::UnsupportedFlags => FileStatusError::Io,
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
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.file_status(file),
            OwnedHandle::Dir(dir) => self.backend.dir_status(dir),
        }
    }

    fn readlink(&self, path: impl Arg) -> Result<alloc::string::String, ReadlinkError> {
        self.readlink_as(self.user_info.into(), path)
    }

    fn readlink_as(
        &self,
        credentials: AccessCredentials<'_>,
        path: impl Arg,
    ) -> Result<alloc::string::String, ReadlinkError> {
        // Open the link itself (`O_PATH` never follows a symlink), then read its
        // target from the backend. `open_as` does not follow symlinks here -- the
        // shim's leaf-following runs above this layer -- so a symlink resolves to
        // its own handle.
        let fd = self
            .open_as(credentials, path, OFlags::PATH, Mode::empty())
            .map_err(|error| match error {
                OpenError::PathError(error) => error.into(),
                _ => ReadlinkError::Io,
            })?;
        let result = {
            let entry = self
                .litebox
                .descriptor_table()
                .entry_handle(&fd)
                .ok_or(ReadlinkError::Io)?;
            let entry = entry.get_entry();
            match &entry.entry.handle {
                OwnedHandle::File(file) => self.backend.read_link(file),
                OwnedHandle::Dir(_) => Err(ReadlinkError::NotASymlink),
            }
        };
        self.close(&fd).unwrap();
        result
    }

    fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        let entry = self.litebox.descriptor_table().entry_handle(fd)?;
        let entry = entry.get_entry();
        if !entry.entry.read_allowed {
            return None;
        }
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.get_static_backing_data(file),
            OwnedHandle::Dir(_) => None,
        }
    }
}

/// A file or a directory handle
enum OwnedHandle {
    File(FileHandle),
    Dir(DirHandle),
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "resolver fd entries carry independent descriptor flags"
)]
struct ResolverEntry<Backend: super::backend::Backend> {
    handle: OwnedHandle,
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
