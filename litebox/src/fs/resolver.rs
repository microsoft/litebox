// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::String;
use alloc::sync::Arc;
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
        CreationMetadata, Handle, HandleRef, PermissionCheck, PermissionInfo, Resolution,
        ResolvedDir, ResolvedTarget, SeekBehavior,
    },
};

/// The north-facing filesystem entry point, generic over a [`Backend`](super::backend::Backend).
pub struct Resolver<
    Platform: sync::RawSyncPrimitivesProvider,
    Backend: super::backend::Backend + 'static,
> {
    litebox: LiteBox<Platform>,
    backend: Backend,
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
        }
    }
}

/// Per-call resolution context.  The user may hold and mutate this as they wish.
///
/// This struct is deliberately cheap to clone.
// NOTE(jayb): I generally dislike getters/setters for fields of a data-like struct (e.g., see
// acting_user and set_acting_user here), but I'm putting these here since I am not yet convinced
// that we won't need more things in the context, nor am I convinced that we might not need the
// ability to lock down how contexts are made/used. In some sense, I am forcing some chokepoints
// here. In the future, we might flatten these out and just allow access to the fields directly.
#[derive(Clone, Debug)]
pub struct Context {
    /// Current working directory.
    cwd: Arc<ResolvedPath>,
    /// Effective user for permission checks.
    user_info: UserInfo,
}

impl Context {
    /// The user that operations on this context act as.
    #[must_use]
    pub fn acting_user(&self) -> UserInfo {
        self.user_info
    }

    /// Set the user that operations on this context act as.
    pub fn set_acting_user(&mut self, user: UserInfo) {
        self.user_info = user;
    }

    /// The current working directory.
    #[must_use]
    pub fn cwd(&self) -> &ResolvedPath {
        &self.cwd
    }

    /// Set the current working directory.
    pub fn set_cwd(&mut self, cwd: ResolvedPath) {
        self.cwd = Arc::new(cwd);
    }

    /// A new default context, anchored at `/` for a non-root user.
    pub fn new() -> Context {
        Self {
            cwd: Arc::new(ResolvedPath { components: vec![] }),
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
    pub fn resolve(&self, path: impl Arg) -> Result<ResolvedPath, PathError> {
        let mut components = if path.as_rust_str()?.starts_with('/') {
            vec![]
        } else {
            self.cwd.components.clone()
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
///
/// Note that a resolved path does not imply that it exists within the file system, merely that it
/// is an absolute normalized path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPath {
    // Note: an empty path is equivalent to `/`.
    components: Vec<String>,
}

impl core::fmt::Display for ResolvedPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for component in &self.components {
            write!(f, "/{component}")?;
        }
        if self.components.is_empty() {
            f.write_str("/")?;
        }
        Ok(())
    }
}

impl ResolvedPath {
    fn parent_and_name(&self) -> Option<(Vec<&str>, &str)> {
        let (name, parent) = self.components.split_last()?;
        Some((parent.iter().map(String::as_str).collect(), name.as_str()))
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    fn parent_dir_and_name<'a>(
        &self,
        context: &Context,
        path: &'a ResolvedPath,
    ) -> Result<Option<(ResolvedDir<'_>, &'a str)>, WalkError> {
        // Keep scoped resolution state alive across the mutation so backend locks stay held.
        let Some((parent_components, name)) = path.parent_and_name() else {
            return Ok(None);
        };
        let parent = match self.resolve_path(context, &parent_components)? {
            Resolution::Found(ResolvedTarget::Dir(parent)) => parent,
            Resolution::Found(ResolvedTarget::File(_)) => {
                return Err(PathError::ComponentNotADirectory.into());
            }
            Resolution::MissingFinal { .. } => return Err(PathError::MissingComponent.into()),
        };
        if let PermissionCheck::ByResolver(permissions) = &parent.permissions {
            Self::check_search_permission(
                context,
                permissions,
                #[cfg(debug_assertions)]
                Some(&parent_components),
            )?;
        }
        Ok(Some((parent, name)))
    }

    /// Whether `context` may add or remove entries in `dir`.
    // TODO(jayb): Prioritize `EROFS` before this permission check runs; currently not an issue due
    // to 0777 from read-only backends, but needs an update then.
    fn can_change_entries_in_dir(context: &Context, dir: &ResolvedDir<'_>) -> bool {
        match &dir.permissions {
            PermissionCheck::ByBackend => true,
            PermissionCheck::ByResolver(permissions) => context.can_write(permissions),
        }
    }

    fn resolve_target(
        &self,
        context: &Context,
        path: &ResolvedPath,
    ) -> Result<ResolvedTarget<'_>, WalkError> {
        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        match self.resolve_path(context, &components)? {
            Resolution::Found(target) => Ok(target),
            Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    fn check_search_permission(
        context: &Context,
        permissions: &PermissionInfo,
        #[cfg(debug_assertions)] absolute_components: Option<&[&str]>,
    ) -> Result<(), WalkError> {
        if !context.can_execute(permissions) {
            return Err(PathError::NoSearchPerms {
                #[cfg(debug_assertions)]
                dir: absolute_components
                    .map(|components| alloc::format!("/{}", components.join("/")))
                    .unwrap_or_default(),
                #[cfg(debug_assertions)]
                perms: permissions.mode,
            }
            .into());
        }
        Ok(())
    }

    fn resolve_path(
        &self,
        context: &Context,
        components: &[&str],
    ) -> Result<Resolution<'_>, WalkError> {
        self.backend
            .resolve(self.backend.root()?, components, &|permissions| {
                Self::check_search_permission(
                    context,
                    permissions,
                    #[cfg(debug_assertions)]
                    None,
                )
            })
            .map_err(|error| {
                #[cfg(debug_assertions)]
                let error = {
                    let mut error = error;
                    if let Some(index) = error.component
                        && let WalkError::PathError(PathError::NoSearchPerms { dir, .. }) =
                            &mut error.error
                    {
                        *dir = alloc::format!("/{}", components[..index].join("/"));
                    }
                    error
                };
                match error.error {
                    WalkError::PathError(PathError::NoSuchFileOrDirectory) => {
                        PathError::MissingComponent.into()
                    }
                    error => error,
                }
            })
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    pub fn open(
        &self,
        context: &Context,
        path: impl Arg,
        mut flags: OFlags,
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

        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        let resolution = self
            .resolve_path(context, &components)
            .map_err(|error| match error {
                WalkError::Io => OpenError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        match resolution {
            Resolution::Found(_) if flags.contains(OFlags::CREAT | OFlags::EXCL) => {
                Err(OpenError::AlreadyExists)
            }
            Resolution::Found(ResolvedTarget::Dir(dir)) => {
                if !path_only
                    && let PermissionCheck::ByResolver(permissions) = &dir.permissions
                    && !context.can_read(permissions)
                {
                    return Err(OpenError::AccessNotAllowed);
                }
                Ok(insert(
                    Handle::Dir(self.backend.open_dir(dir, flags)?),
                    SeekBehavior::NonSeekable,
                ))
            }
            Resolution::Found(ResolvedTarget::File(file)) => {
                // TODO(DO NOT COMMIT): Require write permission for O_TRUNC independently of the
                // access mode; should be fixed up soon
                if !path_only
                    && let PermissionCheck::ByResolver(permissions) = &file.permissions
                    && ((read_allowed && !context.can_read(permissions))
                        || (write_allowed && !context.can_write(permissions)))
                {
                    return Err(OpenError::AccessNotAllowed);
                }
                let file = self.backend.open_file(file, flags)?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(insert(Handle::File(file), seek_behavior))
            }
            Resolution::MissingFinal { parent } if flags.contains(OFlags::CREAT) => {
                let Some(name) = components.last() else {
                    // components is empty => `/` => cannot be missing final
                    unreachable!()
                };
                if !Self::can_change_entries_in_dir(context, &parent) {
                    return Err(OpenError::NoWritePerms);
                }
                let file = self.backend.create_file_at(
                    parent,
                    name,
                    CreationMetadata {
                        mode,
                        owner: context.acting_user(),
                    },
                )?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(insert(Handle::File(file), seek_behavior))
            }
            Resolution::MissingFinal { .. } => Err(PathError::NoSuchFileOrDirectory.into()),
        }
    }

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    pub fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        let mut dt = self.litebox.descriptor_table_mut();
        let removed = dt.remove(fd);
        drop(dt);
        // some backends might block while closing an fd, so we've released the descriptor table
        // lock _before_ we let the backend handle the close.
        drop(removed);
        Ok(())
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

    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    pub fn seek(
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

    /// Truncate the file to the specified length.
    ///
    /// If shorter than existing size, extra data is lost. If longer than existing size, resize by
    /// adding `\0`s.
    ///
    /// If `reset_offset` is true, the offset is reset to zero; otherwise, it remains unchanged.
    pub fn truncate(
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

    /// Change the permissions of a file
    pub fn chmod(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = context.resolve(path)?;
        let target = self
            .resolve_target(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(context, &target) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(target, mode)
    }

    /// Change the owner of a file
    pub fn chown(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = context.resolve(path)?;
        let target = self
            .resolve_target(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(context, &target) {
            return Err(ChownError::NotTheOwner);
        }
        self.backend.chown(target, user, group)
    }

    /// Unlink a file
    pub fn unlink(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
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
        self.backend.unlink_at(parent, name)
    }

    /// Create a new directory
    pub fn mkdir(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
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
        self.backend
            .mkdir_at(
                parent,
                name,
                CreationMetadata {
                    mode,
                    owner: context.acting_user(),
                },
            )
            .map(|_| ())
    }

    /// Remove a directory
    pub fn rmdir(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
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
        self.backend.rmdir_at(parent, name)
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names (explicitly _not_ including `.` or `..`).
    pub fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
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

    /// Obtain the status of a file/directory/... on the file-system.
    #[expect(
        clippy::missing_panics_doc,
        reason = "`CloseError` is uninhabited, so the internal close cannot fail"
    )]
    pub fn file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        let fd = self
            .open(context, path, OFlags::PATH, Mode::empty())
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

    /// Equivalent to [`Self::file_status`], but on an open `fd` instead.
    pub fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<super::FileStatus, FileStatusError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(FileStatusError::ClosedFd)?;
        let entry = entry.get_entry();
        self.backend.status(entry.entry.handle.as_ref())
    }

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., set up via [`super::in_mem::InitialNode::File`]).
    ///
    /// Returns `None` if no static backing data is available/supported.
    pub fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
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
