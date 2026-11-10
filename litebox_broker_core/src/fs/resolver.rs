// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Path management, permission checks, and open-state operations above [`super::backend`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SeekError, SetTimesError,
    SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{
    FileTimeUpdate, FileType, Mode, OFlags, SetFileTimes,
    backend::{
        CreationMetadata, FileCaller, FileTarget, FileTerminal, Handle, HandleRef, LinkTarget,
        LookupContext, PermissionCheck, PermissionInfo, PublishedObject, Resolution, ResolvedDir,
        ResolvedTarget, SeekBehavior,
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
pub struct Resolver<Platform, Backend: super::backend::Backend + 'static> {
    backend: Arc<Backend>,
    caller: Option<FileCaller>,
    publisher: Option<Arc<dyn super::backend::FilePublisher>>,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
    pub(crate) fn process_created(
        &self,
        process: &Arc<crate::BrokerProcess>,
        parent: Option<FileCaller>,
    ) -> crate::Result<alloc::boxed::Box<dyn Send + Sync>> {
        self.backend.process_created(process, parent)
    }

    /// Construct a filesystem resolver over `backend`.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend: Arc::new(backend),
            caller: None,
            publisher: None,
            _sync: PhantomData,
        }
    }

    /// Attach the trusted consumer for process-scoped file publication.
    #[must_use]
    pub fn with_file_publisher(
        mut self,
        publisher: Arc<dyn super::backend::FilePublisher>,
    ) -> Self {
        self.publisher = Some(publisher);
        self
    }

    pub(crate) fn publish_file(
        &self,
        caller: FileCaller,
        key: u64,
        object: PublishedObject,
    ) -> super::FileResult<()> {
        self.publisher
            .as_ref()
            .ok_or(litebox_broker_protocol::fs::FileError::NotSupported)?
            .publish_file(caller, key, object)
    }

    pub(crate) fn publish_data(
        &self,
        caller: FileCaller,
        key: u64,
        data: &[u8],
    ) -> super::FileResult<()> {
        self.publisher
            .as_ref()
            .ok_or(litebox_broker_protocol::fs::FileError::NotSupported)?
            .publish_data(caller, key, data)
    }

    pub(crate) fn for_caller(&self, caller: Option<FileCaller>) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            caller,
            publisher: self.publisher.clone(),
            _sync: PhantomData,
        }
    }

    fn context(&self, user_info: UserInfo) -> Context {
        Context {
            lookup: LookupContext {
                user: user_info,
                caller: self.caller,
            },
        }
    }

    fn entry_backend<'a>(
        &'a self,
        entry: &'a ResolverEntry<Backend>,
    ) -> &'a dyn super::backend::Backend {
        entry.backend.as_deref().unwrap_or(self.backend.as_ref())
    }

    pub(crate) fn retain_file(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<FileTarget, OpenError> {
        if entry.path_only || !entry.read_allowed {
            return Err(OpenError::AccessNotAllowed);
        }
        let Handle::File(handle) = &entry.handle else {
            return Err(OpenError::NoSuchDevice);
        };
        if self
            .entry_backend(entry)
            .status(HandleRef::File(handle))
            .map_err(|_| OpenError::Io)?
            .file_type
            != FileType::RegularFile
        {
            return Err(OpenError::NoSuchDevice);
        }
        let backend: Arc<dyn super::backend::Backend> = match &entry.backend {
            Some(backend) => Arc::clone(backend),
            None => self.backend.clone(),
        };
        Ok(FileTarget {
            backend: Arc::downgrade(&backend),
            handle: handle.clone(),
            display_path: entry.path.clone(),
        })
    }

    /// The object an open entry publishes: its directory, which may be open path-only, or else
    /// its file, retained as [`Self::retain_file`] does.
    pub(crate) fn published_object(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<PublishedObject, OpenError> {
        match &entry.handle {
            Handle::Dir(_) => Ok(PublishedObject::Directory {
                path: entry.path.clone(),
            }),
            Handle::File(_) => self.retain_file(entry).map(PublishedObject::File),
        }
    }
}

/// The position `offset` from the start or from `position`, for content with no end to seek
/// from.
fn seek_without_end(
    position: usize,
    offset: isize,
    whence: SeekWhence,
) -> Result<usize, SeekError> {
    let base = match whence {
        SeekWhence::RelativeToBeginning => 0,
        SeekWhence::RelativeToCurrentOffset => position,
        SeekWhence::RelativeToEnd => return Err(SeekError::InvalidOffset),
    };
    base.checked_add_signed(offset)
        .ok_or(SeekError::InvalidOffset)
}

struct Context {
    lookup: LookupContext,
}

impl Context {
    fn acting_user(&self) -> UserInfo {
        self.lookup.user
    }

    fn can_execute(&self, permissions: &PermissionInfo) -> bool {
        if self.lookup.user.user == permissions.owner.user {
            permissions.mode.contains(Mode::XUSR)
        } else if self.lookup.user.group == permissions.owner.group {
            permissions.mode.contains(Mode::XGRP)
        } else {
            permissions.mode.contains(Mode::XOTH)
        }
    }

    fn can_read(&self, permissions: &PermissionInfo) -> bool {
        if self.lookup.user.user == permissions.owner.user {
            permissions.mode.contains(Mode::RUSR)
        } else if self.lookup.user.group == permissions.owner.group {
            permissions.mode.contains(Mode::RGRP)
        } else {
            permissions.mode.contains(Mode::ROTH)
        }
    }

    fn can_write(&self, permissions: &PermissionInfo) -> bool {
        if self.lookup.user.user == permissions.owner.user {
            permissions.mode.contains(Mode::WUSR)
        } else if self.lookup.user.group == permissions.owner.group {
            permissions.mode.contains(Mode::WGRP)
        } else {
            permissions.mode.contains(Mode::WOTH)
        }
    }
}

/// Absolute normalized path, must only be created by [`Resolver`]'s path resolution.
struct ResolvedPath {
    components: Vec<String>,
    object: Option<FileTarget>,
}

impl ResolvedPath {
    /// The path as an absolute string.
    fn to_absolute(&self) -> String {
        if self.components.is_empty() {
            return String::from("/");
        }
        self.components
            .iter()
            .fold(String::new(), |path, component| path + "/" + component)
    }

    fn parent_and_name(&self) -> Option<(Vec<&str>, &str)> {
        let (name, parent) = self.components.split_last()?;
        Some((parent.iter().map(String::as_str).collect(), name.as_str()))
    }
}

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
    /// Resolve an absolute path to its physical location, following symbolic links.
    pub fn resolve_following_symlinks(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<String, WalkError> {
        let path = self.resolve_path(&self.context(user), path, true, false)?;
        if path.object.is_some() {
            return Err(PathError::InvalidPathname.into());
        }
        Ok(path.to_absolute())
    }

    // XXX(jayb): callers rewalk the result, so this is non-atomic and walks twice; returning the
    // final walking handle alongside the path would fix both.
    // XXX(jayb): if/when we support chroot, we might need to tweak this to not allow "escaping"
    // outside the chrooted part.
    // XXX: broker paths are absolute, so resolution always starts at the root. The client
    // (`litebox::fs::Context::resolve`) also normalizes paths lexically before sending them: it
    // collapses `.`/`..` (so `link/..` names the link's parent rather than, as on Linux, its
    // target's parent) and drops trailing slashes, so `require_directory` and the final `.`/`..`
    // checks below never trigger for guest paths (e.g. `unlink("link/")` removes the link).
    fn resolve_path(
        &self,
        context: &Context,
        path: &str,
        follow_final: bool,
        allow_missing: bool,
    ) -> Result<ResolvedPath, WalkError> {
        let mut pending: VecDeque<String> = path
            .split('/')
            .filter(|part| !part.is_empty())
            .map(String::from)
            .collect();
        let mut require_directory = path.ends_with('/');
        let mut resolved: Vec<String> = Vec::new();
        let mut links = 0;
        // XXX(jayb): each run re-resolves from the root, since `Backend::resolve` consumes its
        // starting directory and does not report symlinks mid-walk.
        while let Some(name) = pending.front() {
            match name.as_str() {
                "." => {
                    pending.pop_front();
                    continue;
                }
                ".." => {
                    pending.pop_front();
                    // The remaining prefix was already resolved (and search-checked) above.
                    resolved.pop();
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
                match self.resolve_components(context, &components) {
                    // Retry from the failing child's parent so a mid-run symlink gets followed.
                    Err(ResolutionError {
                        component,
                        error: WalkError::PathError(PathError::ComponentNotADirectory),
                    }) if end > run_start + 1 => {
                        end = component
                            .filter(|&index| run_start < index && index < end)
                            .unwrap_or(end - 1);
                    }
                    // A caller-held object cannot be walked through, and handing it back would
                    // drop the components after it.
                    result => {
                        break result.map_err(|error| match error.error {
                            WalkError::PathError(PathError::CallerObject(_))
                                if end < resolved.len() || !pending.is_empty() =>
                            {
                                PathError::ComponentNotADirectory.into()
                            }
                            error => error,
                        })?;
                    }
                }
            };
            for part in resolved.drain(end..).rev() {
                pending.push_front(part);
            }
            let final_component = pending.is_empty();
            match resolution {
                Resolution::Found(ResolvedTarget::Dir(dir)) => {
                    // `sub/../f` must still require search permission on `sub`.
                    if !pending.is_empty()
                        && let PermissionCheck::ByResolver(permissions) = &dir.permissions
                    {
                        Self::check_search_permission(context, permissions)?;
                    }
                }
                Resolution::Found(ResolvedTarget::File(file))
                    if file.file_type == FileType::SymbolicLink =>
                {
                    if final_component && !follow_final && !require_directory {
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
                        .resolve_components(context, &parent_components)
                        .map_err(|error| error.error)?
                    else {
                        return Err(PathError::MissingComponent.into());
                    };
                    let target =
                        match self
                            .backend
                            .follow_link_at(&context.lookup, &parent, &name)?
                        {
                            LinkTarget::Path(target) => target,
                            LinkTarget::File(target) => {
                                if !final_component || require_directory {
                                    return Err(PathError::ComponentNotADirectory.into());
                                }
                                resolved.push(name);
                                return Ok(ResolvedPath {
                                    components: resolved,
                                    object: Some(target),
                                });
                            }
                        };
                    if target.starts_with('/') {
                        resolved.clear();
                    }
                    if final_component && target.ends_with('/') {
                        require_directory = true;
                    }
                    for part in target.split('/').filter(|part| !part.is_empty()).rev() {
                        pending.push_front(String::from(part));
                    }
                }
                Resolution::Found(ResolvedTarget::File(_)) => {
                    if !final_component || require_directory {
                        return Err(PathError::ComponentNotADirectory.into());
                    }
                }
                Resolution::MissingFinal { .. } => {
                    if final_component && allow_missing && !require_directory {
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
        Ok(ResolvedPath {
            components: resolved,
            object: None,
        })
    }

    fn parent_dir_and_name(
        &self,
        context: &Context,
        path: &str,
    ) -> Result<Option<(ResolvedDir<'_>, String)>, WalkError> {
        // Keep scoped resolution state alive across the mutation so backend locks stay held.
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            return Ok(None);
        }
        let (parent_path, name) = match trimmed.rsplit_once('/') {
            Some(("", name)) => ("/", name),
            Some(parts) => parts,
            None => ("", trimmed),
        };
        // Entry mutations resolve the parent but retain the final name, so neither a link nor
        // a final `.`/`..` can redirect a removal to an ordinary target directory.
        let parent_path = self.resolve_path(context, parent_path, true, false)?;
        let parent_components: Vec<_> = parent_path.components.iter().map(String::as_str).collect();
        let parent = match self
            .resolve_components(context, &parent_components)
            .map_err(|error| error.error)?
        {
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
            .resolve_with_context(&context.lookup, parent, &[name], &|permissions| {
                Self::check_search_permission(context, permissions)
            })
            .map_err(|error| error.error)?;
        Ok(matches!(resolution, Resolution::Found(_)))
    }

    /// Read a symbolic link's stored target, without following the final link.
    pub fn read_link(&self, user: UserInfo, path: &str) -> Result<String, WalkError> {
        let context = self.context(user);
        let path = self.resolve_path(&context, path, false, false)?;
        let Some((components, name)) = path.parent_and_name() else {
            return Err(PathError::InvalidPathname.into());
        };
        let all: Vec<_> = path.components.iter().map(String::as_str).collect();
        let is_link = matches!(
            self.resolve_components(&context, &all)
                .map_err(|error| error.error)?,
            Resolution::Found(ResolvedTarget::File(file))
                if file.file_type == FileType::SymbolicLink
        );
        if !is_link {
            return Err(PathError::InvalidPathname.into());
        }
        let Resolution::Found(ResolvedTarget::Dir(parent)) = self
            .resolve_components(&context, &components)
            .map_err(|error| error.error)?
        else {
            return Err(PathError::MissingComponent.into());
        };
        self.backend
            .read_link_at_with_context(&context.lookup, &parent, name)
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

    fn resolve_target(
        &self,
        context: &Context,
        path: &ResolvedPath,
    ) -> Result<ResolvedTarget<'_>, WalkError> {
        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        match self
            .resolve_components(context, &components)
            .map_err(|error| error.error)?
        {
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

    fn resolve_components(
        &self,
        context: &Context,
        components: &[&str],
    ) -> Result<Resolution<'_>, ResolutionError> {
        let root = self
            .backend
            .root_with_context(&context.lookup)
            .map_err(|error| ResolutionError {
                component: None,
                error,
            })?;
        self.backend
            .resolve_with_context(&context.lookup, root, components, &|permissions| {
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

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
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
    ) -> Result<ResolverEntry<Backend>, OpenError> {
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
    ) -> Result<ResolverEntry<Backend>, OpenError> {
        let mut entry = self.open_entry(user, path, flags, mode)?;
        if let Handle::File(file) = &entry.handle
            && !entry.path_only
            && matches!(
                self.entry_backend(&entry).terminal(file),
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

        let context = self.context(user);
        let path = self
            .resolve_path(
                &context,
                path,
                !flags.contains(OFlags::NOFOLLOW) && !flags.contains(OFlags::CREAT | OFlags::EXCL),
                flags.contains(OFlags::CREAT),
            )
            .map_err(|error| match error {
                WalkError::Io => OpenError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let nonblocking = flags.contains(OFlags::NONBLOCK);
        let entry = |handle, seek_behavior| ResolverEntry {
            handle,
            backend: None,
            _backend: core::marker::PhantomData,
            read_allowed,
            write_allowed,
            position: 0,
            append_mode,
            nonblocking,
            path_only,
            seek_behavior,
            path: path.to_absolute(),
            controlling_terminal: None,
            listing: None,
        };

        if let Some(target) = &path.object {
            if flags.contains(OFlags::CREAT | OFlags::EXCL) {
                return Err(OpenError::AlreadyExists);
            }
            if flags.contains(OFlags::DIRECTORY) {
                return Err(PathError::ComponentNotADirectory.into());
            }
            if write_allowed || flags.contains(OFlags::TRUNC) {
                return Err(OpenError::InUse);
            }
            let backend = target.backend.upgrade().ok_or(OpenError::Io)?;
            let status = backend
                .status(HandleRef::File(&target.handle))
                .map_err(|_| OpenError::Io)?;
            let permissions = PermissionInfo {
                mode: status.mode,
                owner: status.owner,
                on_read_only_fs: true,
            };
            if !path_only && !context.can_read(&permissions) {
                return Err(OpenError::AccessNotAllowed);
            }
            let behavior = backend.seek_behavior(&target.handle);
            let mut opened = entry(Handle::File(target.handle.clone()), behavior);
            opened.backend = Some(backend);
            opened.path.clone_from(&target.display_path);
            return Ok(opened);
        }

        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        let resolution =
            self.resolve_components(&context, &components)
                .map_err(|error| match error.error {
                    WalkError::Io => OpenError::Io,
                    WalkError::PathError(error) => error.into(),
                })?;
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
                Ok(entry(Handle::File(file), seek_behavior))
            }
            Resolution::MissingFinal { parent } if flags.contains(OFlags::CREAT) => {
                let Some(name) = components.last() else {
                    // components is empty => `/` => cannot be missing final
                    unreachable!()
                };
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
                Ok(entry(Handle::File(file), seek_behavior))
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
            SeekBehavior::PositionBased | SeekBehavior::UnsizedPosition => {
                offset.unwrap_or(entry.position)
            }
        };
        let read = self.entry_backend(entry).read(file, buf, read_offset)?;
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
                    self.entry_backend(entry)
                        .status(HandleRef::File(file))
                        .map_err(|_| WriteError::Io)?
                        .size,
                )
                .map_err(|_| WriteError::Io)?
            }
            SeekBehavior::PositionBased | SeekBehavior::UnsizedPosition => {
                offset.unwrap_or(entry.position)
            }
        };
        let written = self.entry_backend(entry).write(file, buf, write_offset)?;
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
        if entry.path_only {
            return Err(SeekError::NotOpenForSeeking);
        }
        let file = match &entry.handle {
            Handle::File(file) => file,
            Handle::Dir(_) => {
                // A directory position counts entries of the listing snapshot (see
                // `read_dir_snapshot`).
                entry.position = seek_without_end(entry.position, offset, whence)?;
                return Ok(entry.position);
            }
        };

        match entry.seek_behavior {
            SeekBehavior::NonSeekable => Err(SeekError::NonSeekable),
            SeekBehavior::ZeroPosition => Ok(0),
            SeekBehavior::PositionBased => {
                let file_len = self
                    .entry_backend(entry)
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
            SeekBehavior::UnsizedPosition => {
                entry.position = seek_without_end(entry.position, offset, whence)?;
                Ok(entry.position)
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
            SeekBehavior::PositionBased | SeekBehavior::UnsizedPosition => {
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

        self.entry_backend(entry).truncate(file, length)?;
        Ok(())
    }

    /// Change permissions on the object held by an open descriptor.
    ///
    /// Read-only descriptors are accepted; path-only descriptors are not.
    pub fn chmod_handle(
        &self,
        entry: &ResolverEntry<Backend>,
        user: UserInfo,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        if entry.path_only {
            return Err(ChmodError::BadDescriptor);
        }
        if entry.backend.is_some() {
            return Err(ChmodError::ReadOnlyFileSystem);
        }
        match self.backend.chmod_handle(entry.handle.as_ref(), user, mode) {
            // A backend that cannot change an open file itself, such as an overlay whose file is
            // still in a lower layer, changes it through the path it was opened by, while that
            // path still names it. Directory handles may be no more than their path, against
            // which that check proves nothing.
            Err(ChmodError::Unsupported) if matches!(entry.handle, Handle::File(_)) => {
                self.chmod_through_opened_path(entry, user, mode)
            }
            result => result,
        }
    }

    fn chmod_through_opened_path(
        &self,
        entry: &ResolverEntry<Backend>,
        user: UserInfo,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        // Failing to reach the object by its path does not make it nonexistent.
        let walk_error = |error| match error {
            WalkError::Io => ChmodError::Io,
            WalkError::PathError(_) => ChmodError::Unsupported,
        };
        let opened = self
            .backend
            .status(entry.handle.as_ref())
            .map_err(|_| ChmodError::Io)?;
        let context = self.context(user);
        let path = self
            .resolve_path(&context, &entry.path, false, false)
            .map_err(walk_error)?;
        if path.object.is_some() {
            return Err(ChmodError::Unsupported);
        }
        let target = self.resolve_target(&context, &path).map_err(walk_error)?;
        let named = self
            .backend
            .resolved_status(&target)
            .map_err(|_| ChmodError::Io)?;
        if named.node_info != opened.node_info {
            return Err(ChmodError::Unsupported);
        }
        if !Self::may_change_metadata(&context, &target) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(target, mode)
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
        // XXX: set_times re-resolves the open path as the caller;
        // renamed/unlinked/replaced open files fail with EIO, and losing search permission on an
        // ancestor fails with EACCES, where Linux updates the open inode.
        let context = Context::new(user);
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
        let path = self
            .resolve_path(&context, entry.path(), false, false)
            .map_err(map_walk)?;
        let target = self.resolve_target(&context, &path).map_err(map_walk)?;
        let resolved = self
            .backend
            .resolved_status(&target)
            .map_err(|_| SetTimesError::Io)?;
        if (opened.node_info.dev, opened.node_info.ino)
            != (resolved.node_info.dev, resolved.node_info.ino)
        {
            return Err(SetTimesError::Io);
        }
        Self::authorize_set_times(&context, &target, times)?;
        if matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
        ) {
            return Ok(());
        }
        self.backend.set_times(target, times)
    }

    /// Change the permissions of a file
    pub fn chmod(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), ChmodError> {
        let context = self.context(user);
        let path = self
            .resolve_path(&context, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if path.object.is_some() {
            return Err(ChmodError::ReadOnlyFileSystem);
        }
        let target = self
            .resolve_target(&context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &target) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(target, mode)
    }

    /// Change the owner of a file
    pub fn chown(
        &self,
        acting_user: UserInfo,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = self.context(acting_user);
        let path = self
            .resolve_path(&context, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if path.object.is_some() {
            return Err(ChownError::ReadOnlyFileSystem);
        }
        let target = self
            .resolve_target(&context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &target) {
            return Err(ChownError::NotTheOwner);
        }
        self.backend.chown(target, user, group)
    }

    /// Unlink a file
    pub fn unlink(&self, user: UserInfo, path: &str) -> Result<(), UnlinkError> {
        let context = self.context(user);
        let trailing_slash = path.ends_with('/');
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, path)
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
                match self.backend.resolve_with_context(
                    &context.lookup,
                    parent,
                    &[&name],
                    &|permissions| Self::check_search_permission(&context, permissions),
                ) {
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
        let context = self.context(user);
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, linkpath)
                .map_err(|error| match error {
                    WalkError::Io => SymlinkError::Io,
                    WalkError::PathError(error) => error.into(),
                })?
        else {
            return Err(SymlinkError::AlreadyExists);
        };
        if matches!(name.as_str(), "." | "..") {
            return Err(SymlinkError::AlreadyExists);
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
            && let Ok(Some((parent, name))) = self.parent_dir_and_name(&context, linkpath)
            && let Ok(true) = self.name_exists(&context, parent, &name)
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
        let context = self.context(user);
        let map_walk_error = |error| match error {
            WalkError::Io => RenameError::Io,
            WalkError::PathError(error) => error.into(),
        };
        let parent = |path: &str| {
            if path.is_empty() {
                return Err(PathError::NoSuchFileOrDirectory.into());
            }
            if path.contains('\0') {
                return Err(PathError::InvalidPathname.into());
            }
            let Some((parent, name)) = self
                .parent_dir_and_name(&context, path)
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
        let (old_dir, old_name, old_writable) = parent(old_path)?;
        let (new_dir, new_name, new_writable) = parent(new_path)?;
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
                .ok_or(RenameError::Io)?;
            match self
                .backend
                .resolve_with_context(&context.lookup, walking, &[&old_name], &|permissions| {
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

    /// Create a new directory
    pub fn mkdir(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), MkdirError> {
        let context = self.context(user);
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, path)
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
            && let Ok(Some((parent, name))) = self.parent_dir_and_name(&context, path)
            && let Ok(true) = self.name_exists(&context, parent, &name)
        {
            return Err(MkdirError::AlreadyExists);
        }
        result
    }

    /// Remove a directory
    pub fn rmdir(&self, user: UserInfo, path: &str) -> Result<(), RmdirError> {
        let context = self.context(user);
        let Some((parent, name)) =
            self.parent_dir_and_name(&context, path)
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

    /// Return the listing snapshot of an open directory, as [`Self::read_dir`] lists it but
    /// sorted by name.
    ///
    /// The snapshot is owned by the open description, so a position into it stays meaningful
    /// while the directory changes and is shared by every reference to the description. Reading
    /// from `start_index` zero, or before any snapshot exists, takes a fresh snapshot; later
    /// reads reuse it until the next read from the beginning.
    pub(crate) fn read_dir_snapshot(
        &self,
        entry: &mut ResolverEntry<Backend>,
        start_index: usize,
    ) -> Result<Arc<[super::DirEntry]>, ReadDirError> {
        if start_index != 0
            && let Some(listing) = &entry.listing
        {
            return Ok(Arc::clone(listing));
        }
        let mut entries = self.read_dir(entry)?;
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let listing: Arc<[super::DirEntry]> = entries.into();
        entry.listing = Some(Arc::clone(&listing));
        Ok(listing)
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a fresh list of file/directory names including synthesized `.` and `..` entries.
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
        entries.extend(self.entry_backend(entry).list_dir_at(dir.clone())?);
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
        let context = self.context(user);
        let path = self
            .resolve_path(&context, path, follow_symlinks, false)
            .map_err(|error| match error {
                WalkError::Io => FileStatusError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if let Some(target) = &path.object {
            return target.status();
        }
        let target = self
            .resolve_target(&context, &path)
            .map_err(|error| match error {
                WalkError::Io => FileStatusError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        // Unlike an O_PATH open, this must not trigger backend open hooks.
        self.backend.resolved_status(&target)
    }

    /// Equivalent to [`Self::file_status`], but on an open entry instead.
    pub fn handle_status(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<super::FileStatus, FileStatusError> {
        self.entry_backend(entry).status(entry.handle.as_ref())
    }

    /// Shared terminal backing a non-path-only entry.
    pub fn terminal(&self, entry: &ResolverEntry<Backend>) -> Option<Arc<dyn TerminalEndpoint>> {
        match &entry.handle {
            Handle::File(file) if !entry.path_only => {
                match self.entry_backend(entry).terminal(file)? {
                    FileTerminal::Fixed(terminal) => Some(terminal),
                    FileTerminal::OpenersControlling => entry
                        .controlling_terminal
                        .as_ref()
                        .map(|controlling| Arc::clone(&controlling.terminal)),
                }
            }
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
            Handle::File(file) if !entry.path_only => {
                self.entry_backend(entry).readiness_source(file)
            }
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
            Handle::File(file) => self.entry_backend(entry).get_static_backing_data(file),
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
    backend: Option<Arc<dyn super::backend::Backend>>,
    _backend: core::marker::PhantomData<Backend>,
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
    /// A directory's listing snapshot, which its `position` indexes; see
    /// [`Resolver::read_dir_snapshot`].
    listing: Option<Arc<[super::DirEntry]>>,
}

/// A terminal reopened by [`TerminalEndpoint::reopen`], which stays open
/// until this drops.
struct ReopenedTerminal {
    terminal: Arc<dyn TerminalEndpoint>,
    _file: Box<dyn Send + Sync>,
}

impl<Backend: super::backend::Backend> ResolverEntry<Backend> {
    pub(crate) const fn is_path_only(&self) -> bool {
        self.path_only
    }

    /// The open description's position: for a directory, an index into its listing snapshot.
    pub(crate) const fn position(&self) -> usize {
        self.position
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

    /// Whether seeking updates the stored position: for position-based files and directories.
    pub(crate) const fn uses_position(&self) -> bool {
        matches!(
            self.seek_behavior,
            SeekBehavior::PositionBased | SeekBehavior::UnsizedPosition
        ) || matches!(self.handle, Handle::Dir(_))
    }
}
