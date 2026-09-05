// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The path-management/permissions/... layer, that sits above [`super::backend`].

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::fs::UserInfo;
use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::filesystem::{
    FilesystemDirectoryEntry, FilesystemError, FilesystemFileStatus, FilesystemFileType,
    FilesystemNamespace, FilesystemNodeInfo, FilesystemSeekWhence, FilesystemUser,
};
use litebox_platform::sync::RawSyncPrimitivesProvider as RawPlatformSyncPrimitivesProvider;

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError,
    WriteError,
};
use super::{
    FileType, Mode, OFlags,
    backend::{
        CreationMetadata, DeviceIo, DirHandle, Handle, HandleRef, PermissionCheck, PermissionInfo,
        Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkingDirHandle,
    },
};

/// The north-facing filesystem entry point, generic over a [`Backend`](super::backend::Backend).
pub struct Resolver<
    Platform: sync::RawSyncPrimitivesProvider,
    Backend: super::backend::Backend + 'static,
> {
    litebox: LiteBox<Platform>,
    authority: ResolverAuthority<Backend>,
}

enum ResolverAuthority<Backend: super::backend::Backend + 'static> {
    #[cfg(any(test, feature = "local_filesystem"))]
    Local(ResolverCore<Backend>),
    Broker(
        Arc<dyn crate::broker::BrokerControl>,
        FilesystemNamespace,
        core::marker::PhantomData<fn() -> Backend>,
    ),
}

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
    _platform: core::marker::PhantomData<Platform>,
}

/// One open-file description owned by a [`Filesystem`].
pub struct FilesystemOpenFile<Platform: RawPlatformSyncPrimitivesProvider> {
    description: Arc<OpenFileDescription<Platform>>,
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a new resolver over a `backend`.
    #[cfg(any(test, feature = "local_filesystem"))]
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, backend: Backend) -> Self {
        Self {
            litebox: litebox.clone(),
            authority: ResolverAuthority::Local(ResolverCore { backend }),
        }
    }
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Constructs a resolver whose filesystem authority is owned by the broker.
    ///
    /// # Panics
    ///
    /// Panics if `litebox` has no negotiated broker connection.
    #[must_use]
    pub fn new_brokered(litebox: &LiteBox<Platform>) -> Self {
        Self::new_brokered_in_namespace(litebox, FilesystemNamespace::Guest)
    }

    /// Constructs a resolver for the broker-owned Windows registry namespace.
    ///
    /// # Panics
    ///
    /// Panics if `litebox` has no negotiated broker connection.
    #[doc(hidden)]
    #[must_use]
    pub fn new_brokered_windows_registry(litebox: &LiteBox<Platform>) -> Self {
        Self::new_brokered_in_namespace(litebox, FilesystemNamespace::WindowsRegistry)
    }

    fn new_brokered_in_namespace(
        litebox: &LiteBox<Platform>,
        namespace: FilesystemNamespace,
    ) -> Self {
        Self {
            litebox: litebox.clone(),
            authority: ResolverAuthority::Broker(
                litebox
                    .broker_control()
                    .expect("brokered filesystem requires a broker connection"),
                namespace,
                core::marker::PhantomData,
            ),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> DeviceIo for LiteBox<Platform> {
    fn read_stdin(&self, output: &mut [u8]) -> Result<usize, ReadError> {
        LiteBox::read_stdio(self, output).map_err(|_| ReadError::Io)
    }

    fn write_stdio(
        &self,
        stream: crate::stdio::StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, WriteError> {
        LiteBox::write_stdio(self, stream, input).map_err(|_| WriteError::Io)
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ReadError> {
        LiteBox::fill_random(self, output).map_err(|_| ReadError::Io)
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
        path: impl Arg,
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

        let path = context.resolve(path)?;
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
    fn chmod(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = context.resolve(path)?;
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
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = context.resolve(path)?;
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
    fn unlink(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
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

    /// Create a new directory
    fn mkdir(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
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
    fn rmdir(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
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
        path: impl Arg,
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
    #[cfg(any(test, feature = "local_filesystem"))]
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    fn open_file_description(&self, fd: &TypedFd<Self>) -> Option<ResolverDescription<Platform>> {
        let entry = self.litebox.descriptor_table().entry_handle(fd)?;
        let entry = entry.get_entry();
        Some(entry.entry.description.clone())
    }

    /// Opens a file.
    ///
    /// The `mode` is only significant when creating a file.
    pub fn open(
        &self,
        context: &Context,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<TypedFd<Self>, OpenError> {
        let description = match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => {
                ResolverDescription::Local(core.open::<Platform>(context, path, flags, mode)?)
            }
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                let handle = broker
                    .open_file(
                        *namespace,
                        &path,
                        filesystem_user(context.acting_user()),
                        flags.bits(),
                        mode.bits(),
                    )
                    .map_err(|_| OpenError::Io)?
                    .map_err(open_error)?;
                ResolverDescription::Broker(
                    BrokerOpenFileDescription(Arc::new(BrokerOpenFileDescriptionInner {
                        broker: Arc::clone(broker),
                        handle,
                    })),
                    core::marker::PhantomData,
                )
            }
        };
        Ok(self.litebox.descriptor_table_mut().insert(ResolverEntry {
            description,
            _backend: core::marker::PhantomData,
        }))
    }

    /// Closes `fd`.
    ///
    /// Future operations on the descriptor will return closed-descriptor errors.
    pub fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        let mut descriptors = self.litebox.descriptor_table_mut();
        let removed = descriptors.remove(fd);
        drop(descriptors);
        // Backend handles may perform blocking work when the final open description is dropped.
        drop(removed);
        Ok(())
    }

    /// Reads from `fd`, optionally at an explicit offset.
    pub fn read(
        &self,
        fd: &TypedFd<Self>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let description = self.open_file_description(fd).ok_or(ReadError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.read(&self.litebox, &description, buf, offset)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                description
                    .broker
                    .read_file(
                        description.handle,
                        buf,
                        offset
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| ReadError::Io)?,
                    )
                    .map_err(|error| broker_fd_error(error, ReadError::ClosedFd, ReadError::Io))?
                    .map_err(read_error)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Writes to `fd`, optionally at an explicit offset.
    pub fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let description = self.open_file_description(fd).ok_or(WriteError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.write(&self.litebox, &description, buf, offset)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                description
                    .broker
                    .write_file(
                        description.handle,
                        buf,
                        offset
                            .map(u64::try_from)
                            .transpose()
                            .map_err(|_| WriteError::Io)?,
                    )
                    .map_err(|error| broker_fd_error(error, WriteError::ClosedFd, WriteError::Io))?
                    .map_err(write_error)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Repositions the shared offset of `fd`.
    pub fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let description = self.open_file_description(fd).ok_or(SeekError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.seek(&description, offset, whence)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                let offset = i64::try_from(offset).map_err(|_| SeekError::InvalidOffset)?;
                let offset = description
                    .broker
                    .seek_file(description.handle, offset, filesystem_seek_whence(whence))
                    .map_err(|error| broker_fd_error(error, SeekError::ClosedFd, SeekError::Io))?
                    .map_err(seek_error)?;
                usize::try_from(offset).map_err(|_| SeekError::InvalidOffset)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Truncates the file referenced by `fd`.
    pub fn truncate(
        &self,
        fd: &TypedFd<Self>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let description = self
            .open_file_description(fd)
            .ok_or(TruncateError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.truncate(&description, length, reset_offset)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                description
                    .broker
                    .truncate_file(
                        description.handle,
                        u64::try_from(length).map_err(|_| TruncateError::Io)?,
                        reset_offset,
                    )
                    .map_err(|error| {
                        broker_fd_error(error, TruncateError::ClosedFd, TruncateError::Io)
                    })?
                    .map_err(truncate_error)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Changes the permissions of a file.
    pub fn chmod(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.chmod(context, path, mode),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                broker
                    .chmod_file(
                        *namespace,
                        &path,
                        filesystem_user(context.acting_user()),
                        mode.bits(),
                    )
                    .map_err(|_| ChmodError::Io)?
                    .map_err(chmod_error)
            }
        }
    }

    /// Changes the owner of a file.
    pub fn chown(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.chown(context, path, user, group),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                broker
                    .chown_file(
                        *namespace,
                        &path,
                        filesystem_user(context.acting_user()),
                        user,
                        group,
                    )
                    .map_err(|_| ChownError::Io)?
                    .map_err(chown_error)
            }
        }
    }

    /// Unlinks a file.
    pub fn unlink(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.unlink(context, path),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                broker
                    .unlink_file(*namespace, &path, filesystem_user(context.acting_user()))
                    .map_err(|_| UnlinkError::Io)?
                    .map_err(unlink_error)
            }
        }
    }

    /// Creates a directory.
    pub fn mkdir(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.mkdir(context, path, mode),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                broker
                    .mkdir_file(
                        *namespace,
                        &path,
                        filesystem_user(context.acting_user()),
                        mode.bits(),
                    )
                    .map_err(|_| MkdirError::Io)?
                    .map_err(mkdir_error)
            }
        }
    }

    /// Removes a directory.
    pub fn rmdir(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.rmdir(context, path),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                broker
                    .rmdir_file(*namespace, &path, filesystem_user(context.acting_user()))
                    .map_err(|_| RmdirError::Io)?
                    .map_err(rmdir_error)
            }
        }
    }

    /// Reads directory entries from an open directory descriptor.
    pub fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let description = self
            .open_file_description(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.read_dir(&description)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                let entries = description
                    .broker
                    .read_directory(description.handle)
                    .map_err(|error| {
                        broker_fd_error(error, ReadDirError::ClosedFd, ReadDirError::Io)
                    })?
                    .map_err(read_dir_error)?;
                directory_entries(entries)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Obtains the status of the object named by `path`.
    pub fn file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        match &self.authority {
            #[cfg(any(test, feature = "local_filesystem"))]
            ResolverAuthority::Local(core) => core.file_status::<Platform>(context, path),
            ResolverAuthority::Broker(broker, namespace, _) => {
                let path = context.resolve(path)?.to_string();
                let status = broker
                    .path_file_status(*namespace, &path, filesystem_user(context.acting_user()))
                    .map_err(|_| FileStatusError::Io)?
                    .map_err(file_status_error)?;
                file_status(status)
            }
        }
    }

    /// Obtains the status of the object referenced by `fd`.
    pub fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<super::FileStatus, FileStatusError> {
        let description = self
            .open_file_description(fd)
            .ok_or(FileStatusError::ClosedFd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.fd_file_status(&description)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(description, _)) => {
                let status = description
                    .broker
                    .handle_file_status(description.handle)
                    .map_err(|error| {
                        broker_fd_error(error, FileStatusError::ClosedFd, FileStatusError::Io)
                    })?
                    .map_err(file_status_error)?;
                file_status(status)
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }

    /// Gets static backing data for a file, if available.
    pub fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        let description = self.open_file_description(fd)?;
        match (&self.authority, description) {
            #[cfg(any(test, feature = "local_filesystem"))]
            (ResolverAuthority::Local(core), ResolverDescription::Local(description)) => {
                core.get_static_backing_data(&description)
            }
            (ResolverAuthority::Broker(_, _, _), ResolverDescription::Broker(_, _)) => {
                // TODO: Restore zero-copy backing after broker shared-memory objects are available.
                None
            }
            #[cfg(any(test, feature = "local_filesystem"))]
            _ => unreachable!("resolver entry authority must match its resolver"),
        }
    }
}

struct ResolverEntry<Platform: sync::RawSyncPrimitivesProvider, Backend: super::backend::Backend> {
    description: ResolverDescription<Platform>,
    _backend: core::marker::PhantomData<Backend>,
}

enum ResolverDescription<Platform: sync::RawSyncPrimitivesProvider> {
    #[cfg(any(test, feature = "local_filesystem"))]
    Local(Arc<OpenFileDescription<Platform>>),
    Broker(
        BrokerOpenFileDescription,
        core::marker::PhantomData<fn() -> Platform>,
    ),
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for ResolverDescription<Platform> {
    fn clone(&self) -> Self {
        match self {
            #[cfg(any(test, feature = "local_filesystem"))]
            Self::Local(description) => Self::Local(Arc::clone(description)),
            Self::Broker(description, _) => {
                Self::Broker(description.clone(), core::marker::PhantomData)
            }
        }
    }
}

#[derive(Clone)]
struct BrokerOpenFileDescription(Arc<BrokerOpenFileDescriptionInner>);

struct BrokerOpenFileDescriptionInner {
    broker: Arc<dyn crate::broker::BrokerControl>,
    handle: ObjectHandle,
}

impl core::ops::Deref for BrokerOpenFileDescription {
    type Target = BrokerOpenFileDescriptionInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for BrokerOpenFileDescriptionInner {
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
    }
}

const fn filesystem_user(user: UserInfo) -> FilesystemUser {
    FilesystemUser {
        user: user.user,
        group: user.group,
    }
}

const fn filesystem_seek_whence(whence: super::SeekWhence) -> FilesystemSeekWhence {
    match whence {
        super::SeekWhence::RelativeToBeginning => FilesystemSeekWhence::Beginning,
        super::SeekWhence::RelativeToCurrentOffset => FilesystemSeekWhence::Current,
        super::SeekWhence::RelativeToEnd => FilesystemSeekWhence::End,
    }
}

fn broker_fd_error<T>(error: crate::broker::error::BrokerControlError, closed: T, io: T) -> T {
    match error {
        crate::broker::error::BrokerControlError::Broker(
            ErrorCode::UnknownObject | ErrorCode::InvalidRights,
        ) => closed,
        crate::broker::error::BrokerControlError::AssociationFailed
        | crate::broker::error::BrokerControlError::Broker(_) => io,
    }
}

fn path_error(error: FilesystemError) -> Option<PathError> {
    match error {
        FilesystemError::NoSuchFileOrDirectory => Some(PathError::NoSuchFileOrDirectory),
        FilesystemError::NoSearchPermissions => Some(PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir: String::new(),
            #[cfg(debug_assertions)]
            perms: Mode::empty(),
        }),
        FilesystemError::InvalidPathname => Some(PathError::InvalidPathname),
        FilesystemError::MissingComponent => Some(PathError::MissingComponent),
        FilesystemError::ComponentNotDirectory => Some(PathError::ComponentNotADirectory),
        _ => None,
    }
}

fn open_error(error: FilesystemError) -> OpenError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::AccessNotAllowed => OpenError::AccessNotAllowed,
        FilesystemError::NoWritePermissions => OpenError::NoWritePerms,
        FilesystemError::ReadOnlyFilesystem => OpenError::ReadOnlyFileSystem,
        FilesystemError::AlreadyExists => OpenError::AlreadyExists,
        FilesystemError::IsDirectory => OpenError::TruncateError(TruncateError::IsDirectory),
        FilesystemError::NotForWriting => OpenError::TruncateError(TruncateError::NotForWriting),
        FilesystemError::IsTerminalDevice => {
            OpenError::TruncateError(TruncateError::IsTerminalDevice)
        }
        _ => OpenError::Io,
    }
}

fn read_error(error: FilesystemError) -> ReadError {
    match error {
        FilesystemError::NotFile => ReadError::NotAFile,
        FilesystemError::NotForReading => ReadError::NotForReading,
        _ => ReadError::Io,
    }
}

fn write_error(error: FilesystemError) -> WriteError {
    match error {
        FilesystemError::NotFile => WriteError::NotAFile,
        FilesystemError::NotForWriting => WriteError::NotForWriting,
        _ => WriteError::Io,
    }
}

fn seek_error(error: FilesystemError) -> SeekError {
    match error {
        FilesystemError::NotFile => SeekError::NotAFile,
        FilesystemError::InvalidOffset => SeekError::InvalidOffset,
        FilesystemError::NonSeekable => SeekError::NonSeekable,
        _ => SeekError::Io,
    }
}

fn truncate_error(error: FilesystemError) -> TruncateError {
    match error {
        FilesystemError::IsDirectory => TruncateError::IsDirectory,
        FilesystemError::NotForWriting => TruncateError::NotForWriting,
        FilesystemError::IsTerminalDevice => TruncateError::IsTerminalDevice,
        _ => TruncateError::Io,
    }
}

fn chmod_error(error: FilesystemError) -> ChmodError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::NotOwner => ChmodError::NotTheOwner,
        FilesystemError::ReadOnlyFilesystem => ChmodError::ReadOnlyFileSystem,
        _ => ChmodError::Io,
    }
}

fn chown_error(error: FilesystemError) -> ChownError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::NotOwner => ChownError::NotTheOwner,
        FilesystemError::ReadOnlyFilesystem => ChownError::ReadOnlyFileSystem,
        _ => ChownError::Io,
    }
}

fn unlink_error(error: FilesystemError) -> UnlinkError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::NoWritePermissions => UnlinkError::NoWritePerms,
        FilesystemError::IsDirectory => UnlinkError::IsADirectory,
        FilesystemError::ReadOnlyFilesystem => UnlinkError::ReadOnlyFileSystem,
        _ => UnlinkError::Io,
    }
}

fn mkdir_error(error: FilesystemError) -> MkdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::NoWritePermissions => MkdirError::NoWritePerms,
        FilesystemError::AlreadyExists => MkdirError::AlreadyExists,
        FilesystemError::ReadOnlyFilesystem => MkdirError::ReadOnlyFileSystem,
        _ => MkdirError::Io,
    }
}

fn rmdir_error(error: FilesystemError) -> RmdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FilesystemError::NoWritePermissions => RmdirError::NoWritePerms,
        FilesystemError::Busy => RmdirError::Busy,
        FilesystemError::NotEmpty => RmdirError::NotEmpty,
        FilesystemError::NotDirectory => RmdirError::NotADirectory,
        FilesystemError::ReadOnlyFilesystem => RmdirError::ReadOnlyFileSystem,
        _ => RmdirError::Io,
    }
}

fn read_dir_error(error: FilesystemError) -> ReadDirError {
    match error {
        FilesystemError::NotDirectory => ReadDirError::NotADirectory,
        _ => ReadDirError::Io,
    }
}

fn file_status_error(error: FilesystemError) -> FileStatusError {
    path_error(error).map_or(FileStatusError::Io, Into::into)
}

fn file_status(status: FilesystemFileStatus) -> Result<super::FileStatus, FileStatusError> {
    Ok(super::FileStatus {
        file_type: file_type(status.file_type),
        mode: Mode::from_bits_retain(status.mode),
        size: usize::try_from(status.size).map_err(|_| FileStatusError::Io)?,
        owner: UserInfo {
            user: status.owner.user,
            group: status.owner.group,
        },
        node_info: super::NodeInfo {
            dev: usize::try_from(status.node_info.dev).map_err(|_| FileStatusError::Io)?,
            ino: usize::try_from(status.node_info.ino).map_err(|_| FileStatusError::Io)?,
            rdev: status
                .node_info
                .rdev
                .map(|rdev| {
                    usize::try_from(rdev)
                        .ok()
                        .and_then(core::num::NonZeroUsize::new)
                        .ok_or(FileStatusError::Io)
                })
                .transpose()?,
        },
        blksize: usize::try_from(status.block_size).map_err(|_| FileStatusError::Io)?,
    })
}

fn directory_entries(
    entries: Vec<FilesystemDirectoryEntry>,
) -> Result<Vec<super::DirEntry>, ReadDirError> {
    let mut converted = Vec::new();
    converted
        .try_reserve_exact(entries.len())
        .map_err(|_| ReadDirError::Io)?;
    for entry in entries {
        converted.push(super::DirEntry {
            name: entry.name,
            file_type: file_type(entry.file_type),
            ino_info: entry.node_info.map(node_info).transpose()?,
        });
    }
    Ok(converted)
}

const fn file_type(file_type: FilesystemFileType) -> FileType {
    match file_type {
        FilesystemFileType::RegularFile => FileType::RegularFile,
        FilesystemFileType::Directory => FileType::Directory,
        FilesystemFileType::CharacterDevice => FileType::CharacterDevice,
    }
}

fn node_info(node_info: FilesystemNodeInfo) -> Result<super::NodeInfo, ReadDirError> {
    Ok(super::NodeInfo {
        dev: usize::try_from(node_info.dev).map_err(|_| ReadDirError::Io)?,
        ino: usize::try_from(node_info.ino).map_err(|_| ReadDirError::Io)?,
        rdev: node_info
            .rdev
            .map(|rdev| {
                usize::try_from(rdev)
                    .ok()
                    .and_then(core::num::NonZeroUsize::new)
                    .ok_or(ReadDirError::Io)
            })
            .transpose()?,
    })
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider }, Backend: { super::backend::Backend + 'static };
    Resolver<Platform, Backend>;
    @ Platform: { sync::RawSyncPrimitivesProvider }, Backend: { super::backend::Backend + 'static };
    ResolverEntry<Platform, Backend>;
    -> ResolverFd<Platform, Backend>;
}
