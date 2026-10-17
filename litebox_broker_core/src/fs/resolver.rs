// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Path management, permission checks, and open-state operations above [`super::backend`].

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::marker::PhantomData;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{
    FileType, Mode, OFlags,
    backend::{
        CreationMetadata, DirHandle, Handle, HandleRef, PermissionCheck, PermissionInfo,
        Permissioned, SeekBehavior, WalkOutcome, WalkStopReason, WalkingDirHandle,
    },
};
use super::{SeekWhence, UserInfo};
use crate::readiness::ReadinessSource;

/// Maximum number of symbolic links followed while resolving a single path; following more fails
/// with [`PathError::TooManySymlinks`].
const MAX_SYMLINKS: usize = 40;

/// The broker-core filesystem resolver, generic over its synchronization platform and
/// [`Backend`](super::backend::Backend).
pub struct Resolver<Platform, Backend: super::backend::Backend + 'static> {
    backend: Backend,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
    /// Construct a filesystem resolver over `backend`.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
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

/// Absolute normalized path, must only be created by [`Resolver`]'s path resolution.
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

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
    /// Resolve an absolute path to its physical location, following symbolic links.
    pub fn resolve_following_symlinks(
        &self,
        user: UserInfo,
        path: &str,
    ) -> Result<String, WalkError> {
        let path = self.resolve_path(&Context::new(user), path, true, false)?;
        if path.components.is_empty() {
            return Ok(String::from("/"));
        }
        Ok(path
            .components
            .iter()
            .fold(String::new(), |path, component| path + "/" + component))
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
        let mut resolved = Vec::new();
        let mut from = self.backend.root();
        let mut links = 0;
        while let Some(name) = pending.front() {
            match name.as_str() {
                "." => {
                    pending.pop_front();
                    continue;
                }
                ".." => {
                    pending.pop_front();
                    resolved.pop();
                    let components: Vec<_> = resolved.iter().map(String::as_str).collect();
                    from = self
                        .walk_to_directory(context, self.backend.root(), &components, &components)?
                        .handle;
                    continue;
                }
                _ => {}
            }
            let components: Vec<_> = pending
                .iter()
                .take_while(|part| !matches!(part.as_str(), "." | ".."))
                .map(String::as_str)
                .collect();
            let run_len = components.len();
            let outcome = match self.backend.walk_directories(from, &components) {
                Ok(outcome) => outcome,
                Err(WalkError::PathError(PathError::NoSuchFileOrDirectory)) => {
                    if allow_missing && !require_directory && run_len == pending.len() {
                        // A failed batch does not identify the missing component. Validate its
                        // parent before allowing creation of only the final name.
                        let parent: Vec<_> = resolved
                            .iter()
                            .map(String::as_str)
                            .chain(components[..run_len - 1].iter().copied())
                            .collect();
                        self.walk_to_directory(context, self.backend.root(), &parent, &parent)?;
                        resolved.extend(pending);
                        return Ok(ResolvedPath {
                            components: resolved,
                        });
                    }
                    return Err(if run_len == pending.len() {
                        PathError::NoSuchFileOrDirectory
                    } else {
                        PathError::MissingComponent
                    }
                    .into());
                }
                Err(error) => return Err(error),
            };
            let continuing = matches!(outcome.stop_reason, WalkStopReason::Continue);
            Self::check_walk_permissions(
                context,
                &components,
                &outcome,
                if run_len == pending.len() && !continuing {
                    SearchScope::ParentsOnly
                } else {
                    SearchScope::AllComponents
                },
            )?;
            let walked = outcome.components.len();
            assert!(walked <= run_len);
            resolved.extend(pending.drain(..walked));
            match outcome.stop_reason {
                WalkStopReason::CompleteDirectory => {
                    assert_eq!(walked, run_len);
                    from = outcome.last;
                }
                WalkStopReason::StoppedAtNonDirectory {
                    file_type: FileType::SymbolicLink,
                } => {
                    let name = pending.pop_front().expect("symlink is the next component");
                    let final_component = pending.is_empty();
                    if final_component && !follow_final && !require_directory {
                        resolved.push(name);
                        return Ok(ResolvedPath {
                            components: resolved,
                        });
                    }
                    links += 1;
                    if links > MAX_SYMLINKS {
                        return Err(PathError::TooManySymlinks.into());
                    }
                    let target = self.backend.read_link_at(&outcome.last, &name)?;
                    if target.starts_with('/') {
                        resolved.clear();
                        from = self.backend.root();
                    } else {
                        from = outcome.last;
                    }
                    if final_component && target.ends_with('/') {
                        require_directory = true;
                    }
                    for part in target.split('/').filter(|part| !part.is_empty()).rev() {
                        pending.push_front(String::from(part));
                    }
                }
                WalkStopReason::StoppedAtNonDirectory { .. } => {
                    let name = pending
                        .pop_front()
                        .expect("non-directory is the next component");
                    if !pending.is_empty() || require_directory {
                        return Err(PathError::ComponentNotADirectory.into());
                    }
                    resolved.push(name);
                    return Ok(ResolvedPath {
                        components: resolved,
                    });
                }
                WalkStopReason::Continue => {
                    assert!(walked > 0 && walked < run_len);
                    from = outcome.last;
                }
            }
        }
        Ok(ResolvedPath {
            components: resolved,
        })
    }

    fn parent_dir_and_name(
        &self,
        context: &Context,
        path: &str,
    ) -> Result<Option<(WalkedDir<'_>, String)>, WalkError> {
        // Return the walking handle rather than an owned directory handle so backends can keep any
        // locks acquired during path resolution held across the final operation. This lets e.g.
        // "walk parent + mutate child" stay atomic.
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
        let parent = self.walk_to_directory(
            context,
            self.backend.root(),
            &parent_components,
            &parent_components,
        )?;
        Ok(Some((parent, String::from(name))))
    }

    /// Read a symbolic link's stored target, without following the final link.
    pub fn read_link(&self, user: UserInfo, path: &str) -> Result<String, WalkError> {
        let context = Context::new(user);
        let path = self.resolve_path(&context, path, false, false)?;
        let Some((components, name)) = path.parent_and_name() else {
            return Err(PathError::InvalidPathname.into());
        };
        let parent =
            self.walk_to_directory(&context, self.backend.root(), &components, &components)?;
        let outcome = self.backend.walk_directories(parent.handle, &[name])?;
        match outcome.stop_reason {
            WalkStopReason::StoppedAtNonDirectory {
                file_type: FileType::SymbolicLink,
            } => self.backend.read_link_at(&outcome.last, name),
            _ => Err(PathError::InvalidPathname.into()),
        }
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
            WalkStopReason::StoppedAtNonDirectory { .. } => {
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
        absolute_components: &[&str],
    ) -> Result<WalkedDir<'a>, WalkError> {
        if components.is_empty() {
            // TODO(jayb): Decide whether empty walks from a non-root handle need permission checks.
            return Ok(WalkedDir {
                handle: from,
                permissions: None,
            });
        }

        let mut from = from;
        let mut offset = 0;
        loop {
            let outcome = self
                .backend
                .walk_directories(from, &components[offset..])
                .map_err(|error| match error {
                    WalkError::PathError(PathError::NoSuchFileOrDirectory) => {
                        PathError::MissingComponent.into()
                    }
                    error => error,
                })?;
            let continuing = matches!(outcome.stop_reason, WalkStopReason::Continue);
            Self::check_walk_permissions(
                context,
                &absolute_components[offset..],
                &outcome,
                SearchScope::AllComponents,
            )?;
            let walked = outcome.components.len();
            offset += walked;

            match outcome.stop_reason {
                WalkStopReason::CompleteDirectory => {
                    assert_eq!(walked, components.len() - (offset - walked));
                    let permissions = outcome
                        .components
                        .last()
                        .map(|component| component.permissions.clone());
                    return Ok(WalkedDir {
                        handle: outcome.last,
                        permissions,
                    });
                }
                WalkStopReason::StoppedAtNonDirectory { .. } => {
                    return Err(WalkError::PathError(PathError::ComponentNotADirectory));
                }
                WalkStopReason::Continue => {
                    assert!(continuing && walked > 0 && offset < components.len());
                    from = outcome.last;
                }
            }
        }
    }

    fn walk_path<'a>(
        &'a self,
        context: &Context,
        from: WalkingDirHandle<'a>,
        components: &[&str],
        absolute_components: &[&str],
        scope: SearchScope,
    ) -> Result<(WalkOutcome<WalkingDirHandle<'a>>, usize), WalkError> {
        assert_ne!(components, [] as [&str; 0]);
        let mut from = from;
        let mut offset = 0;
        loop {
            let outcome = self.backend.walk_directories(from, &components[offset..])?;
            let continuing = matches!(outcome.stop_reason, WalkStopReason::Continue);
            Self::check_walk_permissions(
                context,
                &absolute_components[offset..],
                &outcome,
                if continuing {
                    SearchScope::AllComponents
                } else {
                    scope
                },
            )?;

            let walked = outcome.components.len();
            offset += walked;
            match outcome.stop_reason {
                WalkStopReason::CompleteDirectory => {
                    assert_eq!(walked, components.len() - (offset - walked));
                    return Ok((outcome, offset));
                }
                WalkStopReason::StoppedAtNonDirectory { .. } if offset == components.len() - 1 => {
                    return Ok((outcome, offset));
                }
                WalkStopReason::StoppedAtNonDirectory { .. } => {
                    return Err(WalkError::PathError(PathError::ComponentNotADirectory));
                }
                WalkStopReason::Continue => {
                    assert!(continuing && walked > 0 && offset < components.len());
                    from = outcome.last;
                }
            }
        }
    }

    fn check_walk_permissions(
        context: &Context,
        absolute_components: &[&str],
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
                litebox_util_log::debug!(
                    dir:% = alloc::format!("/{}", absolute_components[..=idx].join("/")),
                    perms:? = permissions.mode;
                    "no search permission"
                );
                return Err(PathError::NoSearchPerms);
            }
        }
        Ok(())
    }
}

impl<Platform, Backend: super::backend::Backend + 'static> Resolver<Platform, Backend> {
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file
    pub fn open(
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

        let context = Context::new(user);
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
            _backend: core::marker::PhantomData,
            read_allowed,
            write_allowed,
            position: 0,
            append_mode,
            nonblocking,
            path_only,
            seek_behavior,
        };

        if path.components.is_empty() {
            if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                return Err(OpenError::AlreadyExists);
            }
            return Ok(entry(
                Handle::Dir(self.backend.owned_dir_at(self.backend.root(), flags)?),
                SeekBehavior::NonSeekable,
            ));
        }

        let components: Vec<_> = path.components.iter().map(String::as_str).collect();
        let walk = self.walk_path(
            &context,
            self.backend.root(),
            &components,
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
                Ok(entry(
                    Handle::Dir(self.backend.owned_dir_at(outcome.last, flags)?),
                    SeekBehavior::NonSeekable,
                ))
            }
            Ok((outcome, walked))
                if matches!(
                    outcome.stop_reason,
                    WalkStopReason::StoppedAtNonDirectory { .. }
                ) =>
            {
                let name = components[walked];
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                if outcome.stop_reason
                    == (WalkStopReason::StoppedAtNonDirectory {
                        file_type: FileType::SymbolicLink,
                    })
                    && !flags.contains(OFlags::PATH | OFlags::NOFOLLOW)
                {
                    return Err(if flags.contains(OFlags::DIRECTORY) {
                        PathError::ComponentNotADirectory
                    } else {
                        PathError::TooManySymlinks
                    }
                    .into());
                }
                let file = self.backend.open_file_at(outcome.last, name, flags)?;
                if !path_only
                    && let PermissionCheck::ByResolver(permissions) = &file.permissions
                    && ((read_allowed && !context.can_read(permissions))
                        || (write_allowed && !context.can_write(permissions)))
                {
                    return Err(OpenError::AccessNotAllowed);
                }
                let seek_behavior = self.backend.seek_behavior(&file.item);
                Ok(entry(Handle::File(file.item), seek_behavior))
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
                        &parent_components,
                    )
                    .map_err(|error| match error {
                        WalkError::Io => OpenError::Io,
                        WalkError::PathError(error) => error.into(),
                    })?;
                if !Self::can_change_entries_in_dir(&context, &parent) {
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
                Ok(entry(Handle::File(file), seek_behavior))
            }
            Err(error) => match error {
                WalkError::Io => Err(OpenError::Io),
                WalkError::PathError(error) => Err(error.into()),
            },
        }
    }

    pub(crate) fn read_without_position_update(
        &self,
        entry: &ResolverEntry<Backend>,
        buf: &mut [u8],
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
        buf: &mut [u8],
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
        buf: &[u8],
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
        buf: &[u8],
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

    fn may_change_metadata(context: &Context, permissions: &PermissionCheck) -> bool {
        let PermissionCheck::ByResolver(permissions) = permissions else {
            return true;
        };
        let acting = context.acting_user();
        acting.user == UserInfo::ROOT.user || acting.user == permissions.owner.user
    }

    /// Change the permissions of a file
    pub fn chmod(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), ChmodError> {
        let context = Context::new(user);
        let path = self
            .resolve_path(&context, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let handle = self
            .path_handle(&context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChmodError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &handle.permissions) {
            return Err(ChmodError::NotTheOwner);
        }
        self.backend.chmod(handle.item.as_ref(), mode)
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
        let path = self
            .resolve_path(&context, path, true, false)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        let handle = self
            .path_handle(&context, &path)
            .map_err(|error| match error {
                WalkError::Io => ChownError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        if !Self::may_change_metadata(&context, &handle.permissions) {
            return Err(ChownError::NotTheOwner);
        }
        self.backend.chown(handle.item.as_ref(), user, group)
    }

    /// Unlink a file
    pub fn unlink(&self, user: UserInfo, path: &str) -> Result<(), UnlinkError> {
        let context = Context::new(user);
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
        if trailing_slash {
            // Only a directory may be named with a trailing slash, and unlink cannot remove one.
            return Err(
                match self.backend.walk_directories(parent.handle, &[&name]) {
                    Ok(outcome) if outcome.stop_reason == WalkStopReason::CompleteDirectory => {
                        UnlinkError::IsADirectory
                    }
                    Ok(_) => PathError::ComponentNotADirectory.into(),
                    Err(WalkError::Io) => UnlinkError::Io,
                    Err(WalkError::PathError(error)) => error.into(),
                },
            );
        }
        if !Self::can_change_entries_in_dir(&context, &parent) {
            return Err(UnlinkError::NoWritePerms);
        }
        let parent = self
            .owned_parent_dir(parent.handle)
            .map_err(|error| match error {
                WalkError::Io => UnlinkError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.unlink_at(parent, &name)
    }

    /// Create a new directory
    pub fn mkdir(&self, user: UserInfo, path: &str, mode: Mode) -> Result<(), MkdirError> {
        let context = Context::new(user);
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
        if !Self::can_change_entries_in_dir(&context, &parent) {
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
                &name,
                CreationMetadata {
                    mode,
                    owner: context.acting_user(),
                },
            )
            .map(|_| ())
    }

    /// Remove a directory
    pub fn rmdir(&self, user: UserInfo, path: &str) -> Result<(), RmdirError> {
        let context = Context::new(user);
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
        if !Self::can_change_entries_in_dir(&context, &parent) {
            return Err(RmdirError::NoWritePerms);
        }
        let parent = self
            .owned_parent_dir(parent.handle)
            .map_err(|error| match error {
                WalkError::Io => RmdirError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
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
        path: &str,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, FileStatusError> {
        let flags = if follow_symlinks {
            OFlags::PATH
        } else {
            OFlags::PATH | OFlags::NOFOLLOW
        };
        let entry = self
            .open(user, path, flags, Mode::empty())
            .map_err(|error| match error {
                OpenError::PathError(error) => error.into(),
                OpenError::Io
                | OpenError::AccessNotAllowed
                | OpenError::NoWritePerms
                | OpenError::ReadOnlyFileSystem
                | OpenError::AlreadyExists
                | OpenError::TruncateError(_) => FileStatusError::Io,
            })?;
        self.handle_status(&entry)
    }

    /// Equivalent to [`Self::file_status`], but on an open entry instead.
    pub fn handle_status(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<super::FileStatus, FileStatusError> {
        self.backend.status(entry.handle.as_ref())
    }

    /// Whether an open entry refers to a terminal. Path-only entries never do.
    pub fn is_terminal(&self, entry: &ResolverEntry<Backend>) -> bool {
        match &entry.handle {
            Handle::File(file) if !entry.path_only => self.backend.is_terminal(file),
            Handle::File(_) | Handle::Dir(_) => false,
        }
    }

    /// Readiness of an open entry whose reads or writes can fail with `WouldBlock`, or `None` if
    /// they always make progress. Path-only entries never read or write.
    pub fn readiness_source(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Option<Arc<dyn ReadinessSource>> {
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
}

impl<Backend: super::backend::Backend> ResolverEntry<Backend> {
    pub(crate) const fn is_path_only(&self) -> bool {
        self.path_only
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
