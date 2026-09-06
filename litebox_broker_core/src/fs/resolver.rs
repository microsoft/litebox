// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use litebox_platform::sync::{
    self, RawSyncPrimitivesProvider as RawPlatformSyncPrimitivesProvider,
};

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{
    FileType, Mode, OFlags, UserInfo,
    backend::{
        CreationMetadata, DeviceIo, DirHandle, Handle, HandleRef, PermissionCheck, PermissionInfo,
        Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkingDirHandle,
    },
};

struct ResolverCore<Backend: super::backend::Backend + 'static> {
    backend: Backend,
}

struct OpenFileDescription<Platform: RawPlatformSyncPrimitivesProvider> {
    state: sync::Mutex<Platform, OpenFileDescriptionState>,
}

/// Filesystem namespace and open-file-description engine for broker deployments.
pub struct Filesystem<
    Platform: RawPlatformSyncPrimitivesProvider,
    Backend: super::backend::Backend + 'static,
> {
    core: ResolverCore<Backend>,
    _platform: core::marker::PhantomData<fn() -> Platform>,
}

/// One open-file description owned by a [`Filesystem`].
pub struct FilesystemOpenFile<Platform: RawPlatformSyncPrimitivesProvider> {
    description: Arc<OpenFileDescription<Platform>>,
}

impl<Platform: RawPlatformSyncPrimitivesProvider> Clone for FilesystemOpenFile<Platform> {
    fn clone(&self) -> Self {
        Self {
            description: Arc::clone(&self.description),
        }
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "open file descriptions carry independent descriptor flags"
)]
struct OpenFileDescriptionState {
    handle: Handle,
    read_allowed: bool,
    write_allowed: bool,
    position: usize,
    append_mode: bool,
    path_only: bool,
    seek_behavior: SeekBehavior,
}

impl<Platform: RawPlatformSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Filesystem<Platform, Backend>
{
    /// Constructs a filesystem engine over `backend`.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            core: ResolverCore { backend },
            _platform: core::marker::PhantomData,
        }
    }

    /// Opens an absolute path.
    pub fn open(
        &self,
        user: UserInfo,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FilesystemOpenFile<Platform>, OpenError> {
        let context = root_context(user);
        self.core
            .open::<Platform>(&context, path, flags, mode)
            .map(|description| FilesystemOpenFile { description })
    }

    /// Reads from an open file.
    pub fn read(
        &self,
        device_io: &dyn DeviceIo,
        file: &FilesystemOpenFile<Platform>,
        output: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        self.core.read(device_io, &file.description, output, offset)
    }

    /// Writes to an open file.
    pub fn write(
        &self,
        device_io: &dyn DeviceIo,
        file: &FilesystemOpenFile<Platform>,
        input: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        self.core.write(device_io, &file.description, input, offset)
    }

    /// Repositions an open file.
    pub fn seek(
        &self,
        file: &FilesystemOpenFile<Platform>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        self.core.seek(&file.description, offset, whence)
    }

    /// Truncates an open file.
    pub fn truncate(
        &self,
        file: &FilesystemOpenFile<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        self.core.truncate(&file.description, length, reset_offset)
    }

    /// Reads all entries from an open directory.
    pub fn read_dir(
        &self,
        file: &FilesystemOpenFile<Platform>,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
        self.core.read_dir(&file.description)
    }

    /// Returns status for an absolute path.
    pub fn file_status(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<super::FileStatus, FileStatusError> {
        self.core.file_status::<Platform>(&root_context(user), path)
    }

    /// Returns status for an open file.
    pub fn handle_status(
        &self,
        file: &FilesystemOpenFile<Platform>,
    ) -> Result<super::FileStatus, FileStatusError> {
        self.core.fd_file_status(&file.description)
    }

    /// Gets static backing data for an open file, when supported by its backend.
    #[must_use]
    pub fn get_static_backing_data(
        &self,
        file: &FilesystemOpenFile<Platform>,
    ) -> Option<&'static [u8]> {
        self.core.get_static_backing_data(&file.description)
    }

    /// Changes mode bits for an absolute path.
    pub fn chmod(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), ChmodError> {
        self.core.chmod(&root_context(user), path, mode)
    }

    /// Changes ownership for an absolute path.
    pub fn chown(
        &self,
        acting_user: UserInfo,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.core
            .chown(&root_context(acting_user), path, user, group)
    }

    /// Removes a file at an absolute path.
    pub fn unlink(&self, user: UserInfo, path: &str) -> Result<(), UnlinkError> {
        self.core.unlink(&root_context(user), path)
    }

    /// Creates a directory at an absolute path.
    pub fn mkdir(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), MkdirError> {
        self.core.mkdir(&root_context(user), path, mode)
    }

    /// Removes a directory at an absolute path.
    pub fn rmdir(&self, user: UserInfo, path: &str) -> Result<(), RmdirError> {
        self.core.rmdir(&root_context(user), path)
    }
}

fn root_context(user: UserInfo) -> Context {
    let mut context = Context::new();
    context.set_acting_user(user);
    context
}
/// Per-call resolution context.
// NOTE(jayb): I generally dislike getters/setters for fields of a data-like struct (e.g., see
// acting_user and set_acting_user here), but I'm putting these here since I am not yet convinced
// that we won't need more things in the context, nor am I convinced that we might not need the
// ability to lock down how contexts are made/used. In some sense, I am forcing some chokepoints
// here. In the future, we might flatten these out and just allow access to the fields directly.
#[derive(Clone, Debug)]
struct Context {
    /// Current working directory.
    cwd: Arc<ResolvedPath>,
    /// Effective user for permission checks.
    user_info: UserInfo,
}

impl Context {
    /// The user that operations on this context act as.
    #[must_use]
    fn acting_user(&self) -> UserInfo {
        self.user_info
    }

    /// Set the user that operations on this context act as.
    fn set_acting_user(&mut self, user: UserInfo) {
        self.user_info = user;
    }

    /// A new default context, anchored at `/` for a non-root user.
    fn new() -> Context {
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
    fn resolve(&self, path: &str) -> ResolvedPath {
        let mut components = if path.starts_with('/') {
            vec![]
        } else {
            self.cwd.components.clone()
        };
        for component in path.split('/') {
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
        ResolvedPath { components }
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
struct ResolvedPath {
    // Note: an empty path is equivalent to `/`.
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

/// Which directories along a walk must grant search (execute) permission.
#[derive(Clone, Copy)]
enum SearchScope {
    /// Every walked directory, including a final directory component, must be searchable.
    AllComponents,
    /// The directories leading to the object the path names must be searchable; target is not
    /// checked.
    ParentsOnly,
    /// Like [`SearchScope::ParentsOnly`], but the final directory component is checked to be
    /// readable.
    AndReadableTarget,
}

impl<Backend: super::backend::Backend + 'static> ResolverCore<Backend> {
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

    /// Resolve `path` to an owned handle on the file or directory it names, plus how permissions
    /// on it are to be checked.
    ///
    /// The handle is taken with [`OFlags::PATH`], as it addresses the object for operations that
    /// do not read or write its contents, and thus needs no access permissions on it.
    fn path_handle(
        &self,
        context: &Context,
        path: &ResolvedPath,
    ) -> Result<Permissioned<Handle>, WalkError> {
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
            // A backend root reports no permission metadata, so the backend is left to enforce
            // whatever it wants on it.
            return Ok(Permissioned {
                item: Handle::Dir(root),
                permissions: PermissionCheck::ByBackend,
            });
        }
        let (outcome, walked) = self.walk_path(
            context,
            self.backend.root(),
            &components,
            #[cfg(debug_assertions)]
            &components,
            SearchScope::ParentsOnly,
        )?;
        match outcome.stop_reason {
            WalkStopReason::CompleteDirectory => {
                let permissions = outcome
                    .components
                    .last()
                    .map_or(PermissionCheck::ByBackend, |component| {
                        component.permissions.clone()
                    });
                let dir = self
                    .backend
                    .owned_dir_at(outcome.last, OFlags::PATH)
                    .map_err(map_open_error)?;
                Ok(Permissioned {
                    item: Handle::Dir(dir),
                    permissions,
                })
            }
            WalkStopReason::StoppedAtNonDirectory => {
                let file = self
                    .backend
                    .open_file_at(outcome.last, components[walked], OFlags::PATH)
                    .map_err(map_open_error)?;
                Ok(Permissioned {
                    item: Handle::File(file.item),
                    permissions: file.permissions,
                })
            }
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
            SearchScope::AllComponents,
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
        scope: SearchScope,
    ) -> Result<(WalkOutcome<WalkingDirHandle<'a>>, usize), WalkError> {
        assert!(!components.is_empty());
        let outcome = self.backend.walk_directories(from, components)?;
        Self::check_walk_permissions(
            context,
            #[cfg(debug_assertions)]
            absolute_components,
            &outcome,
            scope,
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
        scope: SearchScope,
    ) -> Result<(), PathError> {
        for (idx, walked) in outcome.components.iter().enumerate() {
            let PermissionCheck::ByResolver(permissions) = &walked.permissions else {
                continue;
            };
            let is_target_dir = idx + 1 == outcome.components.len()
                && matches!(outcome.stop_reason, WalkStopReason::CompleteDirectory);
            let allowed = match (is_target_dir, scope) {
                (true, SearchScope::ParentsOnly) => continue,
                (true, SearchScope::AndReadableTarget) => context.can_read(permissions),
                _ => context.can_execute(permissions),
            };
            if !allowed {
                // TODO(jayb): a [`SearchScope::AndReadableTarget`] target denying *read* permission
                // reports `NoSearchPerms` too. Clean up during filesystem errors overhaul.
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
        Ok(())
    }
}

impl<Backend: super::backend::Backend + 'static> ResolverCore<Backend> {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    fn open<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        context: &Context,
        path: &str,
        mut flags: OFlags,
        mode: Mode,
    ) -> Result<Arc<OpenFileDescription<Platform>>, OpenError> {
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
            return Err(OpenError::Io);
        }
        let path_only = flags.contains(OFlags::PATH);
        if path_only {
            // For `PATH`, we restrict what other flags are allowed, so a missing path cannot lead
            // to a creation, etc.
            flags &= OFlags::PATH | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        }

        let path = context.resolve(path);
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let open_description = |handle, seek_behavior| {
            Arc::new(OpenFileDescription {
                state: sync::Mutex::new(OpenFileDescriptionState {
                    handle,
                    read_allowed,
                    write_allowed,
                    position: 0,
                    append_mode,
                    path_only,
                    seek_behavior,
                }),
            })
        };

        if path.components.is_empty() {
            if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                return Err(OpenError::AlreadyExists);
            }
            return Ok(open_description(
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
            if path_only {
                SearchScope::ParentsOnly
            } else if read_allowed {
                SearchScope::AndReadableTarget
            } else {
                // XXX: necessary due to #884/#888, ideally we would not have this path hit
                SearchScope::AllComponents
            },
        );
        match walk {
            Ok((outcome, _)) if outcome.stop_reason == WalkStopReason::CompleteDirectory => {
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                Ok(open_description(
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
                Ok(open_description(Handle::File(file.item), seek_behavior))
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
                let file = self.backend.create_file_at(
                    parent,
                    name,
                    CreationMetadata {
                        mode,
                        owner: context.acting_user(),
                    },
                )?;
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(open_description(Handle::File(file), seek_behavior))
            }
            Err(error) => match error {
                WalkError::Io => Err(OpenError::Io),
                WalkError::PathError(error) => Err(error.into()),
            },
        }
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
    fn read<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        device_io: &dyn DeviceIo,
        description: &OpenFileDescription<Platform>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let mut state = description.state.lock();
        let file = match &state.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(ReadError::NotAFile),
        };
        let seek_behavior = state.seek_behavior;
        if !state.read_allowed {
            return Err(ReadError::NotForReading);
        }
        if state.path_only {
            return Err(ReadError::NotForReading);
        }

        let read_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased => offset.unwrap_or(state.position),
        };
        let read = self.backend.read(device_io, file, buf, read_offset)?;
        if matches!(seek_behavior, SeekBehavior::PositionBased) && offset.is_none() {
            state.position = read_offset.checked_add(read).unwrap();
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
    fn write<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        device_io: &dyn DeviceIo,
        description: &OpenFileDescription<Platform>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let mut state = description.state.lock();
        let file = match &state.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(WriteError::NotAFile),
        };
        let seek_behavior = state.seek_behavior;
        if !state.write_allowed {
            return Err(WriteError::NotForWriting);
        }
        if state.path_only {
            return Err(WriteError::NotForWriting);
        }

        let write_offset = match seek_behavior {
            SeekBehavior::NonSeekable | SeekBehavior::ZeroPosition => 0,
            SeekBehavior::PositionBased if state.append_mode && offset.is_none() => {
                self.backend
                    .status(HandleRef::File(file))
                    .map_err(|_| WriteError::Io)?
                    .size
            }
            SeekBehavior::PositionBased => offset.unwrap_or(state.position),
        };
        let written = self.backend.write(device_io, file, buf, write_offset)?;
        if matches!(seek_behavior, SeekBehavior::PositionBased) && offset.is_none() {
            state.position = write_offset.checked_add(written).unwrap();
        }
        Ok(written)
    }

    /// Reposition read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    fn seek<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        description: &OpenFileDescription<Platform>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let mut state = description.state.lock();
        let file = match &state.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(SeekError::NotAFile),
        };
        if state.path_only {
            return Err(SeekError::NonSeekable);
        }

        match state.seek_behavior {
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
                    super::SeekWhence::RelativeToCurrentOffset => state.position,
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
                state.position = new_position;
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
    fn truncate<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        description: &OpenFileDescription<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let mut state = description.state.lock();
        let file = match &state.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => return Err(TruncateError::IsDirectory),
        };
        if !state.write_allowed {
            return Err(TruncateError::NotForWriting);
        }
        if state.path_only {
            return Err(TruncateError::NotForWriting);
        }

        self.backend.truncate(file, length)?;
        if reset_offset {
            state.position = 0;
        }
        Ok(())
    }

    fn may_change_metadata(context: &Context, permissions: &PermissionCheck) -> bool {
        let PermissionCheck::ByResolver(permissions) = permissions else {
            return true;
        };
        let acting = context.acting_user();
        acting.user == UserInfo::ROOT.user || acting.user == permissions.owner.user
    }

    /// Change the permissions of a file
    fn chmod(&self, context: &Context, path: &str, mode: Mode) -> Result<(), ChmodError> {
        let path = context.resolve(path);
        let handle = self
            .path_handle(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(context, &handle.permissions) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(handle.item.as_ref(), mode)
    }

    /// Change the owner of a file
    fn chown(
        &self,
        context: &Context,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = context.resolve(path);
        let handle = self
            .path_handle(context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(context, &handle.permissions) {
            return Err(ChownError::NotTheOwner);
        }
        self.backend.chown(handle.item.as_ref(), user, group)
    }

    /// Unlink a file
    fn unlink(&self, context: &Context, path: &str) -> Result<(), UnlinkError> {
        let path = context.resolve(path);
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

    /// Create a new directory
    fn mkdir(&self, context: &Context, path: &str, mode: Mode) -> Result<(), MkdirError> {
        let path = context.resolve(path);
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
    fn rmdir(&self, context: &Context, path: &str) -> Result<(), RmdirError> {
        let path = context.resolve(path);
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

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names (explicitly _not_ including `.` or `..`).
    fn read_dir<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        description: &OpenFileDescription<Platform>,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let state = description.state.lock();
        if state.path_only {
            return Err(ReadDirError::NotADirectory);
        }
        let dir = match &state.handle {
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
    fn file_status<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        context: &Context,
        path: &str,
    ) -> Result<super::FileStatus, FileStatusError> {
        let description = self
            .open::<Platform>(context, path, OFlags::PATH, Mode::empty())
            .map_err(|error| match error {
                OpenError::PathError(error) => error.into(),
                OpenError::Io
                | OpenError::AccessNotAllowed
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::TruncateError(_) => FileStatusError::Io,
            })?;
        self.fd_file_status(&description)
    }

    /// Equivalent to [`Self::file_status`], but on an open `fd` instead.
    fn fd_file_status<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        description: &OpenFileDescription<Platform>,
    ) -> Result<super::FileStatus, FileStatusError> {
        let state = description.state.lock();
        self.backend.status(state.handle.as_ref())
    }

    /// Get static backing data for a file, if available and supported.
    ///
    /// This method returns the (entire) underlying static byte slice if the file's contents are
    /// backed by borrowed static data (e.g., set up via [`super::in_mem::InitialNode::File`]).
    ///
    /// Returns `None` if no static backing data is available/supported.
    fn get_static_backing_data<Platform: RawPlatformSyncPrimitivesProvider>(
        &self,
        description: &OpenFileDescription<Platform>,
    ) -> Option<&'static [u8]> {
        let state = description.state.lock();
        match &state.handle {
            Handle::File(file) => self.backend.get_static_backing_data(file),
            Handle::Dir(_) => None,
        }
    }
}
