// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Path management, permission checks, and open-state operations above [`super::backend`].

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::marker::PhantomData;

use litebox_broker_protocol::authority::{Principal, Scope, Subject};
use litebox_broker_protocol::fs::{FileLockOperation, FileSecurityUpdate};
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use litebox_platform::sync::RawSyncPrimitivesProvider;

use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RenameError, ResolutionError, RmdirError, SeekError, SetSecurityError,
    SetTimesError, SymlinkError, TruncateError, UnlinkError, WalkError, WriteError,
};
use super::{
    FileTimeUpdate, FileType, Mode, OFlags, SetFileTimes,
    backend::{
        CreationMetadata, EntryRemoval, EntryRename, FileTerminal, Handle, HandleRef, OpenChecks,
        Opener, PermissionCheck, PermissionInfo, Resolution, ResolvedDir, ResolvedTarget,
        SeekBehavior, with_owners,
    },
};
use super::{SeekWhence, UserInfo};
use crate::authority::Authority;
use crate::descriptor::mutation::{MutationContext, MutationError};
use crate::descriptor::profile::FileSystemProfile;
use crate::descriptor::{FileKind as DescriptorKind, RemovalDenied, Rights, SecurityDescriptor};
use crate::readiness::ReadinessSource;
use crate::terminal::TerminalEndpoint;

/// Maximum number of symbolic links followed while resolving a single path; following more fails
/// with [`PathError::TooManySymlinks`].
const MAX_SYMLINKS: usize = 40;

/// The broker-core filesystem resolver, generic over its synchronization platform and
/// [`Backend`](super::backend::Backend).
///
/// A resolver either checks POSIX users against POSIX mode and owner metadata ([`Self::new`]), or
/// authorizes subjects through the descriptors of broker-owned objects
/// ([`Self::with_credentials`]). Each refuses callers of the other kind.
pub struct Resolver<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
{
    backend: Backend,
    flocks: super::flock::FlockTable<Platform>,
    /// The profile that bounds guest-stored descriptors, for a resolver that authorizes subjects.
    profile: Option<FileSystemProfile>,
    _sync: PhantomData<fn() -> Platform>,
}

impl<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a filesystem resolver over `backend` that checks [`Caller::User`]s against POSIX
    /// mode and owner metadata.
    #[must_use]
    pub fn new(backend: Backend) -> Self {
        Self {
            backend,
            flocks: super::flock::FlockTable::new(),
            profile: None,
            _sync: PhantomData,
        }
    }

    /// Construct a filesystem resolver over `backend` that authorizes [`Caller::Subject`]s through
    /// the descriptors of broker-owned objects, storing only guest descriptors that `profile`
    /// admits.
    ///
    /// Objects whose backend enforces its own permissions ([`PermissionCheck::ByBackend`]), or
    /// whose metadata the broker does not own ([`PermissionInfo::reported_posix`]), cannot be
    /// reached through it: every lookup in or of one fails with [`PathError::NoSearchPerms`].
    #[must_use]
    pub fn with_credentials(backend: Backend, profile: FileSystemProfile) -> Self {
        Self {
            profile: Some(profile),
            ..Self::new(backend)
        }
    }

    /// The context for an operation by `caller`, which must be of the kind this resolver checks.
    fn context<'c>(&self, caller: impl Into<Caller<'c>>) -> Result<Context<'c>, PathError> {
        match (caller.into(), self.profile) {
            (Caller::User(user), None) => Ok(Context::Legacy(user)),
            (Caller::Subject { subject, authority }, Some(profile))
                if subject.scope == Scope::Access && authority.admits(subject) =>
            {
                Ok(Context::Credentialed(MutationContext {
                    subject,
                    authority,
                    profile,
                }))
            }
            _ => Err(PathError::NoSearchPerms),
        }
    }

    /// The context in which `caller` changes the contents of a file through an open entry: none
    /// on a resolver that checks POSIX users, where content changes leave descriptors unchanged,
    /// and the subject's on one that authorizes subjects. Fails with `refused` for a caller of
    /// the wrong kind, or for no caller on a resolver that authorizes subjects.
    fn content_context<'c, E>(
        &self,
        caller: Option<Caller<'c>>,
        refused: E,
    ) -> Result<Option<MutationContext<'c>>, E> {
        match caller.map(|caller| self.context(caller)) {
            None if self.profile.is_none() => Ok(None),
            Some(Ok(Context::Legacy(_))) => Ok(None),
            Some(Ok(Context::Credentialed(context))) => Ok(Some(context)),
            None | Some(Err(_)) => Err(refused),
        }
    }
}

/// Who performs a [`Resolver`] operation.
#[derive(Clone, Copy)]
pub enum Caller<'a> {
    /// A POSIX user, for a resolver built with [`Resolver::new`].
    User(UserInfo),
    /// A subject, for a resolver built with [`Resolver::with_credentials`].
    Subject {
        /// The acting subject.
        subject: &'a Subject,
        /// The authority under which the broker admitted `subject`.
        authority: &'a Authority,
    },
}

impl From<UserInfo> for Caller<'_> {
    fn from(user: UserInfo) -> Self {
        Self::User(user)
    }
}

#[derive(Clone, Copy)]
enum Context<'a> {
    Legacy(UserInfo),
    Credentialed(MutationContext<'a>),
}

impl Context<'_> {
    fn can_execute(&self, permissions: &PermissionInfo) -> bool {
        self.allows(
            permissions,
            [Mode::XUSR, Mode::XGRP, Mode::XOTH],
            Rights::TRAVERSE,
        )
    }

    fn can_read(&self, permissions: &PermissionInfo) -> bool {
        let rights = match permissions.descriptor().map(SecurityDescriptor::kind) {
            Some(DescriptorKind::Directory) => Rights::LIST,
            _ => Rights::READ,
        };
        self.allows(permissions, [Mode::RUSR, Mode::RGRP, Mode::ROTH], rights)
    }

    fn can_write(&self, permissions: &PermissionInfo) -> bool {
        self.allows(
            permissions,
            [Mode::WUSR, Mode::WGRP, Mode::WOTH],
            Rights::WRITE,
        )
    }

    /// Whether the caller may access an object with `permissions` as a legacy caller would with
    /// the owner, group or other mode bit of `bits`, or a subject would with `rights`.
    fn allows(&self, permissions: &PermissionInfo, bits: [Mode; 3], rights: Rights) -> bool {
        match self {
            Self::Legacy(user) => {
                let Some(descriptor) = permissions.descriptor() else {
                    // Backends that combine others search self-enforcing ones without asking.
                    return true;
                };
                let Some(mode) = descriptor.mode() else {
                    return false;
                };
                let [owner_bit, group_bit, other_bit] = bits;
                mode.contains(if user.user_principal() == descriptor.owner() {
                    owner_bit
                } else if user.group_principal() == descriptor.group() {
                    group_bit
                } else {
                    other_bit
                })
            }
            Self::Credentialed(context) => permissions
                .broker_descriptor()
                .filter(|descriptor| context.profile.honors(descriptor))
                .is_some_and(|descriptor| descriptor.allows_file(context.subject, rights)),
        }
    }
}

/// The POSIX mode and owner of a [`PermissionCheck::ByResolver`] object, for legacy callers.
fn checked_posix_metadata(permissions: &PermissionCheck) -> Option<(Mode, Principal)> {
    let PermissionCheck::ByResolver(info) = permissions else {
        return None;
    };
    let descriptor = info.descriptor()?;
    Some((descriptor.mode()?, descriptor.owner()))
}

/// The descriptor that a new object of `kind` requested with `mode` by `context` in a directory
/// with descriptor `parent` stores, if `context` may create it there; `denied` maps why not.
fn creation_descriptor<E>(
    context: &MutationContext<'_>,
    parent: &SecurityDescriptor,
    kind: DescriptorKind,
    mode: Mode,
    denied: impl FnOnce(MutationError) -> E,
) -> Result<SecurityDescriptor, E> {
    let (owner, group) = context.creation_ownership(parent);
    SecurityDescriptor::from_mode(kind, owner, group, mode & Mode::SUPPORTED)
        .map_err(|_| MutationError::UnsupportedForm)
        .and_then(|requested| context.create(parent, requested))
        .map_err(denied)
}

/// Checks whether the subject may make this rename: remove the source and any
/// replaced entry, add an entry to the new parent, and move a directory to a new parent.
fn authorize_rename(
    rename: &EntryRename<'_>,
    context: &MutationContext<'_>,
) -> Result<(), RenameError> {
    let subject = context.subject;
    if ![rename.old_parent, rename.new_parent, rename.source]
        .iter()
        .all(|d| context.profile.honors(d))
        || rename.replaced.is_some_and(|d| !context.profile.honors(d))
    {
        return Err(RenameError::NoWritePerms);
    }
    let denied = |error| match error {
        RemovalDenied::Access => RenameError::NoWritePerms,
        RemovalDenied::NotOwner => RenameError::NotOwner,
    };
    rename
        .old_parent
        .check_remove(rename.source, subject)
        .map_err(denied)?;
    if !rename
        .new_parent
        .allows_file(subject, Rights::TRAVERSE | Rights::ADD_ENTRY)
    {
        return Err(RenameError::NoWritePerms);
    }
    if let Some(replaced) = rename.replaced {
        rename
            .new_parent
            .check_remove(replaced, subject)
            .map_err(denied)?;
    }
    if !rename.same_parent
        && rename.source.kind() == DescriptorKind::Directory
        && !rename.source.allows_file(subject, Rights::REPARENT)
    {
        return Err(RenameError::NoWritePerms);
    }
    Ok(())
}

fn set_security_error(error: MutationError) -> SetSecurityError {
    match error {
        MutationError::Denied => SetSecurityError::NotPermitted,
        MutationError::UnsupportedForm => SetSecurityError::UnsupportedForm,
        MutationError::WrongKind => SetSecurityError::WrongKind,
    }
}

/// Absolute normalized path, must only be created by [`Resolver`]'s path resolution.
struct ResolvedPath {
    components: Vec<String>,
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
}

impl<Platform: RawSyncPrimitivesProvider, Backend: super::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Mount a fresh in-memory filesystem on an existing directory.
    ///
    /// Resolvers that authorize subjects refuse this with [`FileError::NotSupported`].
    ///
    /// [`FileError::NotSupported`]: litebox_broker_protocol::fs::FileError::NotSupported
    // XXX(jayb): Once guests can request other mount kinds, replace this with a mount taking the
    // requested kind; the permission checks here are backend-independent.
    pub fn mount_in_mem<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
    ) -> Result<(), litebox_broker_protocol::fs::FileError> {
        use super::composer::{Composer, MountError};
        use super::in_mem::{InMem, InitialNode};
        use super::service::file_walk_error;
        use litebox_broker_protocol::fs::FileError;

        let context = self
            .context(caller)
            .map_err(|error| file_walk_error(error.into()))?;
        // TODO: decide who may mount, and the descriptor of the new root, for subjects.
        let Context::Legacy(user) = context else {
            return Err(FileError::NotSupported);
        };
        let path = self
            .resolve_path(&context, path, true, false)
            .map_err(file_walk_error)?;
        let ResolvedTarget::Dir(target) = self
            .resolve_target(&context, &path)
            .map_err(file_walk_error)?
        else {
            return Err(FileError::NotDirectory);
        };
        if user.user != UserInfo::ROOT.user {
            // XXX(jayb): Linux requires CAP_SYS_ADMIN; we let non-root mount over directories they own.
            if checked_posix_metadata(&target.permissions)
                .is_none_or(|(_, owner)| owner != user.user_principal())
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
                    .resolve_components(&context, &components)
                    .map_err(|error| file_walk_error(error.error))?
                else {
                    return Err(FileError::NotOwner);
                };
                if !checked_posix_metadata(&ancestor.permissions).is_some_and(|(mode, owner)| {
                    owner == user.user_principal() || !mode.contains(Mode::SVTX)
                }) {
                    return Err(FileError::NotOwner);
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

    /// Resolve an absolute path to its physical location, following symbolic links.
    pub fn resolve_following_symlinks<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
    ) -> Result<String, WalkError> {
        Ok(self
            .resolve_path(&self.context(caller)?, path, true, false)?
            .to_absolute())
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
        context: &Context<'_>,
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
                    result => break result.map_err(|error| error.error)?,
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
                    links += 1;
                    if links > MAX_SYMLINKS {
                        return Err(PathError::TooManySymlinks.into());
                    }
                    let target = self.link_target(context, file, &resolved)?;
                    resolved.pop();
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
        })
    }

    fn parent_dir_and_name(
        &self,
        context: &Context<'_>,
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
        context: &Context<'_>,
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

    /// Read a symbolic link's stored target, without following the final link.
    pub fn read_link<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
    ) -> Result<String, WalkError> {
        let context = self.context(caller)?;
        let path = self.resolve_path(&context, path, false, false)?;
        match self.resolve_target(&context, &path)? {
            ResolvedTarget::File(file) if file.file_type == FileType::SymbolicLink => {
                self.link_target(&context, file, &path.components)
            }
            _ => Err(PathError::InvalidPathname.into()),
        }
    }

    fn link_target(
        &self,
        context: &Context<'_>,
        file: super::backend::ResolvedFile<'_>,
        path: &[String],
    ) -> Result<String, WalkError> {
        if matches!(context, Context::Credentialed(_)) {
            return self.backend.read_resolved_link(&file);
        }
        // Legacy backends may only implement named reads. Release walking locks before re-entry.
        drop(file);
        let (name, components) = path.split_last().ok_or(PathError::InvalidPathname)?;
        let components: Vec<_> = components.iter().map(String::as_str).collect();
        let Resolution::Found(ResolvedTarget::Dir(parent)) = self
            .resolve_components(context, &components)
            .map_err(|error| error.error)?
        else {
            return Err(PathError::MissingComponent.into());
        };
        self.backend.read_link_at(&parent, name)
    }

    /// Check that `context` may add or remove entries in `dir`: `read_only` if `dir` is on a
    /// read-only filesystem, whatever its mode (Linux checks the mount before permissions), else
    /// `no_write_perms` if a legacy `context` can't write `dir`. Subjects are authorized by the
    /// checked backend operation that makes the change, against the entries it changes.
    fn check_dir_entries_change<E>(
        context: &Context<'_>,
        dir: &ResolvedDir<'_>,
        read_only: E,
        no_write_perms: E,
    ) -> Result<(), E> {
        match (&dir.permissions, context) {
            (PermissionCheck::ByResolver(permissions), _) if permissions.on_read_only_fs() => {
                Err(read_only)
            }
            (PermissionCheck::ByResolver(permissions), Context::Legacy(_))
                if !context.can_write(permissions) =>
            {
                Err(no_write_perms)
            }
            (PermissionCheck::ByBackend, Context::Credentialed(_)) => Err(no_write_perms),
            (PermissionCheck::ByBackend | PermissionCheck::ByResolver(_), _) => Ok(()),
        }
    }

    fn resolve_target(
        &self,
        context: &Context<'_>,
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
        context: &Context<'_>,
        permissions: &PermissionInfo,
    ) -> Result<(), WalkError> {
        if !context.can_execute(permissions) {
            litebox_util_log::debug!(descriptor:? = permissions.descriptor(); "no search permission");
            return Err(PathError::NoSearchPerms.into());
        }
        Ok(())
    }

    /// Resolve `components` from the root. For a subject, every directory searched and the
    /// object (or missing object's parent) reached must be broker-owned.
    fn resolve_components(
        &self,
        context: &Context<'_>,
        components: &[&str],
    ) -> Result<Resolution<'_>, ResolutionError> {
        let unowned = |permissions: &PermissionCheck| {
            matches!(context, Context::Credentialed(actor)
                if !matches!(permissions, PermissionCheck::ByResolver(info)
                    if info.broker_descriptor().is_some_and(|d| actor.profile.honors(d))))
        };
        let refused = ResolutionError {
            component: None,
            error: PathError::NoSearchPerms.into(),
        };
        let root = self.backend.root().map_err(|error| ResolutionError {
            component: None,
            error,
        })?;
        // A self-enforcing backend searches its own directories without asking.
        if unowned(&root.permissions) {
            return Err(refused);
        }
        self.backend
            .resolve(root, components, &|permissions| {
                Self::check_search_permission(context, permissions)
            })
            .and_then(|resolution| {
                let permissions = match &resolution {
                    Resolution::Found(target) => target.permissions(),
                    Resolution::MissingFinal { parent } => &parent.permissions,
                };
                if unowned(permissions) {
                    return Err(refused);
                }
                Ok(resolution)
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
    /// Opens a file
    ///
    /// The `mode` is only significant when creating a file. Opening a file
    /// that refers to the opener's controlling terminal for I/O fails with
    /// [`OpenError::NoSuchDevice`], as if the opener had none (see
    /// [`open_with_controlling_terminal`](Self::open_with_controlling_terminal)).
    pub fn open<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        flags: OFlags,
        mode: Mode,
    ) -> Result<ResolverEntry<Backend>, OpenError> {
        self.open_with_controlling_terminal(caller, path, flags, mode, &|| None)
    }

    /// Opens a file like [`open`](Self::open), binding a file that refers to
    /// the opener's controlling terminal to `controlling_terminal()`, which it
    /// holds open (see [`TerminalEndpoint::reopen`]) and through which its I/O
    /// then goes.
    ///
    /// Like Linux, opening such a file for I/O fails with
    /// [`OpenError::NoSuchDevice`] if the opener has no controlling terminal,
    /// while opening it only for path-based operations does not.
    pub fn open_with_controlling_terminal<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        flags: OFlags,
        mode: Mode,
        controlling_terminal: &dyn Fn() -> Option<Arc<dyn TerminalEndpoint>>,
    ) -> Result<ResolverEntry<Backend>, OpenError> {
        let mut entry = self.open_entry(self.context(caller)?, path, flags, mode)?;
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

    /// Opens a file for `context`.
    ///
    /// For a subject, path-only opens need no rights on the object itself, and a truncating open
    /// is a content change by the subject (see [`MutationContext::content_change`]); other opens,
    /// even for writing, leave the file's descriptor unchanged. The backend admits a subject's
    /// open against the file's current descriptor (see [`Backend::open_file_checked`]), and an
    /// object it creates for an admitted subject in [`Scope::Access`] (such as a pseudo-terminal
    /// subsidiary) belongs to the subject's owner and group.
    ///
    /// [`Backend::open_file_checked`]: super::backend::Backend::open_file_checked
    fn open_entry(
        &self,
        context: Context<'_>,
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
            path: path.to_absolute(),
            controlling_terminal: None,
        };

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
                    if wants_write && permissions.on_read_only_fs() {
                        return Err(OpenError::ReadOnlyFileSystem);
                    }
                    if (read_allowed && !context.can_read(permissions))
                        || (wants_write && !context.can_write(permissions))
                    {
                        return Err(OpenError::AccessNotAllowed);
                    }
                }
                let file = match &context {
                    Context::Legacy(_) => self.backend.open_file(file, flags)?,
                    Context::Credentialed(context) => {
                        let rights = if path_only {
                            Rights::empty()
                        } else {
                            let mut rights = Rights::empty();
                            rights.set(Rights::READ, read_allowed);
                            rights.set(Rights::WRITE, wants_write);
                            rights
                        };
                        let subject = context.subject;
                        self.backend.open_file_checked(
                            file,
                            flags,
                            &OpenChecks {
                                opener: Opener {
                                    owner: subject.owner,
                                    group: subject.group,
                                },
                                admit: &|descriptor| {
                                    if context.profile.honors(descriptor)
                                        && (rights.is_empty()
                                            || descriptor.allows_file(subject, rights))
                                    {
                                        Ok(())
                                    } else {
                                        Err(OpenError::AccessNotAllowed)
                                    }
                                },
                                content_change: &|descriptor| context.content_change(descriptor),
                            },
                        )?
                    }
                };
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
                let file = match &context {
                    Context::Legacy(user) => self.backend.create_file_at(
                        parent,
                        name,
                        CreationMetadata::posix(FileType::RegularFile, mode, *user),
                    )?,
                    Context::Credentialed(context) => {
                        self.backend.create_file_checked(parent, name, &|parent| {
                            creation_descriptor(
                                context,
                                parent,
                                DescriptorKind::File,
                                mode,
                                |error| match error {
                                    MutationError::Denied => OpenError::NoWritePerms,
                                    MutationError::WrongKind => {
                                        PathError::ComponentNotADirectory.into()
                                    }
                                    MutationError::UnsupportedForm => OpenError::Io,
                                },
                            )
                        })?
                    }
                };
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

    /// Like [`Self::write_as`], but leaves the file offset unchanged, returning the offset written
    /// at along with the number of bytes written.
    pub fn write_without_position_update_as<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        entry: &ResolverEntry<Backend>,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<(usize, usize), WriteError> {
        self.write_entry(Some(caller.into()), entry, buf, offset)
    }

    pub(super) fn write_entry(
        &self,
        caller: Option<Caller<'_>>,
        entry: &ResolverEntry<Backend>,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<(usize, usize), WriteError> {
        let writer = self.content_context(caller, WriteError::Io)?;
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
        let written = match &writer {
            None => self.backend.write(file, buf, write_offset)?,
            Some(writer) => self
                .backend
                .write_checked(file, buf, write_offset, &|descriptor| {
                    writer.content_change(descriptor);
                })?,
        };
        Ok((written, write_offset))
    }

    /// Write from a buffer to a file descriptor at `offset`, on a resolver built with
    /// [`Self::new`], which leaves the file's metadata unchanged.
    ///
    /// On a resolver built with [`Self::with_credentials`], where each write is a content change
    /// by a subject (see [`Self::write_as`]), this fails with [`WriteError::Io`].
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
        self.write_updating_position(None, entry, buf, offset)
    }

    /// Write like [`Self::write`] for `caller`, whatever opened `entry`.
    ///
    /// For a subject, a write of at least one byte is a content change (see
    /// [`MutationContext::content_change`]): with it, and under the same lock, the file loses
    /// the elevation grants that the subject may not preserve. Failed and empty writes change
    /// nothing.
    ///
    /// # Panics
    ///
    /// Panics if the updated file offset would overflow `usize`.
    pub fn write_as<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        entry: &mut ResolverEntry<Backend>,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        self.write_updating_position(Some(caller.into()), entry, buf, offset)
    }

    pub(super) fn write_updating_position(
        &self,
        caller: Option<Caller<'_>>,
        entry: &mut ResolverEntry<Backend>,
        buf: &dyn WriteBuffer,
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let (written, write_offset) = self.write_entry(caller, entry, buf, offset)?;
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

    /// Truncate the file to the specified length, on a resolver built with [`Self::new`], which
    /// leaves the file's metadata unchanged.
    ///
    /// On a resolver built with [`Self::with_credentials`], where each truncation is a content
    /// change by a subject (see [`Self::truncate_as`]), this fails with [`TruncateError::Io`].
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
        self.truncate_updating_position(None, entry, length, reset_offset)
    }

    /// Truncate like [`Self::truncate`] for `caller`, whatever opened `entry`.
    ///
    /// For a subject, a successful truncation is a content change (see
    /// [`MutationContext::content_change`]) even if it keeps the length, as on Linux: with it,
    /// and under the same lock, the file loses the elevation grants that the subject may not
    /// preserve. Failed truncations change nothing.
    pub fn truncate_as<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        entry: &mut ResolverEntry<Backend>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        self.truncate_updating_position(Some(caller.into()), entry, length, reset_offset)
    }

    pub(super) fn truncate_updating_position(
        &self,
        caller: Option<Caller<'_>>,
        entry: &mut ResolverEntry<Backend>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        self.truncate_entry(caller, entry, length)?;
        if reset_offset {
            entry.position = 0;
        }
        Ok(())
    }

    /// Like [`Self::truncate_as`], but leaves the file offset unchanged.
    pub fn truncate_without_position_update_as<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        entry: &ResolverEntry<Backend>,
        length: usize,
    ) -> Result<(), TruncateError> {
        self.truncate_entry(Some(caller.into()), entry, length)
    }

    pub(super) fn truncate_entry(
        &self,
        caller: Option<Caller<'_>>,
        entry: &ResolverEntry<Backend>,
        length: usize,
    ) -> Result<(), TruncateError> {
        let writer = self.content_context(caller, TruncateError::Io)?;
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

        match &writer {
            None => self.backend.truncate(file, length)?,
            Some(writer) => self.backend.truncate_checked(file, length, &|descriptor| {
                writer.content_change(descriptor);
            })?,
        }
        Ok(())
    }

    /// Whether legacy `user` may change the metadata of an object with `permissions`.
    fn may_change_metadata(user: UserInfo, permissions: &PermissionCheck) -> bool {
        let PermissionCheck::ByResolver(permissions) = permissions else {
            return true;
        };
        let Some(descriptor) = permissions.descriptor() else {
            return true;
        };
        user.user == UserInfo::ROOT.user || descriptor.owner() == user.user_principal()
    }

    fn authorize_set_times(
        user: UserInfo,
        target: &ResolvedTarget<'_>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        if matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
        ) {
            return Ok(());
        }
        let PermissionCheck::ByResolver(permissions) = target.permissions() else {
            return Ok(());
        };
        if permissions.on_read_only_fs() {
            return Err(SetTimesError::ReadOnlyFileSystem);
        }
        if Self::may_change_metadata(user, target.permissions()) {
            return Ok(());
        }
        // Only both-NOW lets write access substitute for ownership.
        if matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Now, FileTimeUpdate::Now)
        ) {
            return if Context::Legacy(user).can_write(permissions) {
                Ok(())
            } else {
                Err(SetTimesError::AccessNotAllowed)
            };
        }
        Err(SetTimesError::NotTheOwner)
    }

    /// Whether `subject` may make the timestamp update `times` to an object with `descriptor`:
    /// setting both to the current time needs [`Rights::TOUCH`], and others
    /// [`Rights::WRITE_ATTRIBUTES`].
    fn authorize_subject_set_times(
        subject: &Subject,
        descriptor: &SecurityDescriptor,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        let both_now = matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Now, FileTimeUpdate::Now)
        );
        let granted =
            descriptor.granted_file_rights(subject, Rights::TOUCH | Rights::WRITE_ATTRIBUTES);
        if granted.contains(Rights::WRITE_ATTRIBUTES)
            || (both_now && granted.contains(Rights::TOUCH))
        {
            Ok(())
        } else if both_now {
            Err(SetTimesError::AccessNotAllowed)
        } else {
            Err(SetTimesError::NotTheOwner)
        }
    }

    /// Change timestamps of the object identified by an open entry.
    pub fn set_times<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        entry: &ResolverEntry<Backend>,
        times: &SetFileTimes,
    ) -> Result<(), SetTimesError> {
        // XXX: set_times re-resolves the open path as the caller;
        // renamed/unlinked/replaced open files fail with EIO, and losing search permission on an
        // ancestor fails with EACCES, where Linux updates the open inode.
        let context = self.context(caller)?;
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
        if matches!(
            (times.access, times.modify),
            (FileTimeUpdate::Omit, FileTimeUpdate::Omit)
        ) {
            return Ok(());
        }
        match context {
            Context::Legacy(user) => {
                Self::authorize_set_times(user, &target, times)?;
                self.backend.set_times(target, times)
            }
            Context::Credentialed(context) => {
                if let PermissionCheck::ByResolver(permissions) = target.permissions()
                    && permissions.on_read_only_fs()
                {
                    return Err(SetTimesError::ReadOnlyFileSystem);
                }
                self.backend
                    .set_times_checked(target, times, &|descriptor| {
                        if !context.profile.honors(descriptor) {
                            return Err(SetTimesError::AccessNotAllowed);
                        }
                        Self::authorize_subject_set_times(context.subject, descriptor, times)
                    })
            }
        }
    }

    /// Replace the descriptor of the object at `path`, following symbolic links, with `requested`
    /// as authorized by [`MutationContext::set_security`].
    ///
    /// Only resolvers that authorize subjects store descriptors; others refuse this with
    /// [`SetSecurityError::UnsupportedForm`].
    pub fn set_security<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        requested: &SecurityDescriptor,
    ) -> Result<(), SetSecurityError> {
        let Context::Credentialed(context) = self.context(caller)? else {
            return Err(SetSecurityError::UnsupportedForm);
        };
        let target =
            self.resolve_existing(&Context::Credentialed(context), path, |error| match error {
                WalkError::Io => SetSecurityError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
        self.backend.update_security(target, &|current| {
            context
                .set_security(
                    current,
                    requested.try_clone().map_err(|_| SetSecurityError::Io)?,
                )
                .map_err(set_security_error)
        })
    }

    /// Applies a partial update to the current inode descriptor under the backend's lock.
    pub(super) fn update_security(
        &self,
        caller: Caller<'_>,
        path: &str,
        update: FileSecurityUpdate,
    ) -> Result<(), SetSecurityError> {
        let context = self.context(caller)?;
        let Context::Credentialed(actor) = context else {
            return Err(SetSecurityError::UnsupportedForm);
        };
        let target = self.resolve_existing(&context, path, |error| match error {
            WalkError::Io => SetSecurityError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        self.update_target_security(&actor, target, update)
    }

    /// Resolve `path`, following symbolic links, to an existing object.
    fn resolve_existing<E>(
        &self,
        context: &Context<'_>,
        path: &str,
        map: impl Fn(WalkError) -> E,
    ) -> Result<ResolvedTarget<'_>, E> {
        let path = self
            .resolve_path(context, path, true, false)
            .map_err(&map)?;
        self.resolve_target(context, &path).map_err(map)
    }

    fn update_target_security(
        &self,
        context: &MutationContext<'_>,
        target: ResolvedTarget<'_>,
        update: FileSecurityUpdate,
    ) -> Result<(), SetSecurityError> {
        self.backend.update_security(target, &|current| {
            let owner = update.owner.unwrap_or_else(|| current.owner());
            let group = update.group.unwrap_or_else(|| current.group());
            let requested = match update.mode {
                Some(mode) => SecurityDescriptor::from_mode(current.kind(), owner, group, mode)
                    .map_err(|_| SetSecurityError::UnsupportedForm)?,
                None => {
                    with_owners(current, owner, group).ok_or(SetSecurityError::UnsupportedForm)?
                }
            };
            context
                .set_security(current, requested)
                .map_err(set_security_error)
        })
    }

    /// Change the permissions of a file
    ///
    /// For a subject, this replaces the file's descriptor with the mode-form one for `mode` and
    /// its current owner and group, as authorized by [`MutationContext::set_security`].
    pub fn chmod<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let context = self.context(caller)?;
        let target = self.resolve_existing(&context, path, |error| match error {
            WalkError::Io => ChmodError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        match context {
            Context::Legacy(user) => {
                if !Self::may_change_metadata(user, target.permissions()) {
                    return Err(ChmodError::NotTheOwner);
                }
                self.backend.chmod(target, mode)
            }
            Context::Credentialed(context) => self
                .update_target_security(
                    &context,
                    target,
                    FileSecurityUpdate {
                        mode: Some(mode & Mode::SUPPORTED),
                        ..Default::default()
                    },
                )
                .map_err(|error| match error {
                    SetSecurityError::NotPermitted => ChmodError::NotTheOwner,
                    SetSecurityError::ReadOnlyFileSystem => ChmodError::ReadOnlyFileSystem,
                    SetSecurityError::IsSymlink => ChmodError::IsSymlink,
                    SetSecurityError::PathError(error) => error.into(),
                    SetSecurityError::UnsupportedForm
                    | SetSecurityError::WrongKind
                    | SetSecurityError::Io => ChmodError::Io,
                }),
        }
    }

    /// Change the owner of a file
    ///
    /// For a subject, `user` and `group` name POSIX principals, and the file keeps its access
    /// with the new owners, as authorized by [`MutationContext::set_security`].
    pub fn chown<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = self.context(caller)?;
        let target = self.resolve_existing(&context, path, |error| match error {
            WalkError::Io => ChownError::Io,
            WalkError::PathError(error) => error.into(),
        })?;
        match context {
            Context::Legacy(acting_user) => {
                if !Self::may_change_metadata(acting_user, target.permissions()) {
                    return Err(ChownError::NotTheOwner);
                }
                self.backend.chown(target, user, group)
            }
            Context::Credentialed(context) => self
                .update_target_security(
                    &context,
                    target,
                    FileSecurityUpdate {
                        owner: user.map(|id| Principal::posix_user(id.into())),
                        group: group.map(|id| Principal::posix_group(id.into())),
                        mode: None,
                    },
                )
                .map_err(|error| match error {
                    SetSecurityError::NotPermitted => ChownError::NotTheOwner,
                    SetSecurityError::ReadOnlyFileSystem => ChownError::ReadOnlyFileSystem,
                    SetSecurityError::IsSymlink => ChownError::IsSymlink,
                    SetSecurityError::PathError(error) => error.into(),
                    SetSecurityError::UnsupportedForm
                    | SetSecurityError::WrongKind
                    | SetSecurityError::Io => ChownError::Io,
                }),
        }
    }

    /// Unlink a file
    ///
    /// A subject must be allowed to remove the entry from its directory
    /// ([`SecurityDescriptor::allows_remove`]), checked atomically with the removal.
    pub fn unlink<'c>(&self, caller: impl Into<Caller<'c>>, path: &str) -> Result<(), UnlinkError> {
        let context = self.context(caller)?;
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
        match context {
            Context::Legacy(_) => self.backend.unlink_at(parent, &name),
            Context::Credentialed(context) => {
                self.backend.unlink_checked(parent, &name, &|removal| {
                    Self::authorize_removal(
                        &context,
                        removal,
                        UnlinkError::NoWritePerms,
                        UnlinkError::NotOwner,
                    )
                })
            }
        }
    }

    fn authorize_removal<E>(
        context: &MutationContext<'_>,
        removal: &EntryRemoval<'_>,
        denied: E,
        not_owner: E,
    ) -> Result<(), E> {
        if !context.profile.honors(removal.parent) || !context.profile.honors(removal.entry) {
            return Err(denied);
        }
        removal
            .parent
            .check_remove(removal.entry, context.subject)
            .map_err(|why| match why {
                RemovalDenied::Access => denied,
                RemovalDenied::NotOwner => not_owner,
            })
    }

    /// Create a symbolic link without resolving its target.
    pub fn symlink<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        target: &str,
        linkpath: &str,
    ) -> Result<(), SymlinkError> {
        if target.is_empty() {
            return Err(PathError::NoSuchFileOrDirectory.into());
        }
        if target.as_bytes().contains(&0) || linkpath.as_bytes().contains(&0) {
            return Err(PathError::InvalidPathname.into());
        }
        let context = self.context(caller)?;
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
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        let result = match &context {
            Context::Legacy(user) => self.backend.symlink_at(
                parent,
                &name,
                target,
                CreationMetadata::posix(FileType::SymbolicLink, mode, *user),
            ),
            Context::Credentialed(context) => {
                self.backend
                    .symlink_checked(parent, &name, target, &|parent| {
                        creation_descriptor(context, parent, DescriptorKind::File, mode, |error| {
                            match error {
                                MutationError::Denied => SymlinkError::NoWritePerms,
                                MutationError::WrongKind => {
                                    PathError::ComponentNotADirectory.into()
                                }
                                MutationError::UnsupportedForm => SymlinkError::NotSupported,
                            }
                        })
                    })
            }
        };
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
    ///
    /// A subject must be allowed to remove the source from its directory, add an entry to the
    /// destination directory, remove any replaced entry from it, and, for a directory moved to
    /// another parent, [`Rights::REPARENT`] it; all checked atomically with the rename.
    pub fn rename<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        old_path: &str,
        new_path: &str,
    ) -> Result<(), RenameError> {
        let context = self.context(caller)?;
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
            let probe = match context {
                Context::Legacy(_) => self
                    .backend
                    .rename_at(old_dir, &old_name, new_dir, &new_name),
                // The backend asks before mutating anything, so this cannot rename.
                Context::Credentialed(_) => {
                    self.backend
                        .rename_checked(old_dir, &old_name, new_dir, &new_name, &|_| {
                            Err(RenameError::ReadOnlyFileSystem)
                        })
                }
            };
            return match probe {
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
        match context {
            // XXX(jayb): like unlink, legacy rename omits sticky-bit checks and write permission
            // on a moved directory for updating `..`.
            Context::Legacy(_) => self
                .backend
                .rename_at(old_dir, &old_name, new_dir, &new_name),
            Context::Credentialed(context) => {
                self.backend
                    .rename_checked(old_dir, &old_name, new_dir, &new_name, &|rename| {
                        if require_directory && rename.source.kind() != DescriptorKind::Directory {
                            return Err(PathError::ComponentNotADirectory.into());
                        }
                        authorize_rename(rename, &context)
                    })
            }
        }
    }

    /// Create a new directory
    pub fn mkdir<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let context = self.context(caller)?;
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
        let result = match &context {
            Context::Legacy(user) => self.backend.mkdir_at(
                parent,
                &name,
                CreationMetadata::posix(FileType::Directory, mode, *user),
            ),
            Context::Credentialed(context) => {
                self.backend.mkdir_checked(parent, &name, &|parent| {
                    creation_descriptor(context, parent, DescriptorKind::Directory, mode, |error| {
                        match error {
                            MutationError::Denied => MkdirError::NoWritePerms,
                            MutationError::WrongKind => PathError::ComponentNotADirectory.into(),
                            MutationError::UnsupportedForm => MkdirError::Io,
                        }
                    })
                })
            }
        }
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
    ///
    /// A subject must be allowed to remove the entry from its directory
    /// ([`SecurityDescriptor::allows_remove`]), checked atomically with the removal.
    pub fn rmdir<'c>(&self, caller: impl Into<Caller<'c>>, path: &str) -> Result<(), RmdirError> {
        let context = self.context(caller)?;
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
        match context {
            Context::Legacy(_) => self.backend.rmdir_at(parent, &name),
            Context::Credentialed(context) => {
                self.backend.rmdir_checked(parent, &name, &|removal| {
                    Self::authorize_removal(
                        &context,
                        removal,
                        RmdirError::NoWritePerms,
                        RmdirError::NotOwner,
                    )
                })
            }
        }
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names including synthesized `.` and `..` entries.
    pub fn read_dir(
        &self,
        entry: &ResolverEntry<Backend>,
    ) -> Result<Vec<super::DirEntry>, ReadDirError> {
        if entry.path_only || !entry.read_allowed {
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
    pub fn file_status<'c>(
        &self,
        caller: impl Into<Caller<'c>>,
        path: &str,
        follow_symlinks: bool,
    ) -> Result<super::FileStatus, FileStatusError> {
        let context = self.context(caller)?;
        let path = self
            .resolve_path(&context, path, follow_symlinks, false)
            .map_err(|error| match error {
                WalkError::Io => FileStatusError::Io,
                WalkError::PathError(error) => error.into(),
            })?;
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
    /// Returns `None` if the entry is not open for reading or has no static backing data.
    pub fn get_static_backing_data(&self, entry: &ResolverEntry<Backend>) -> Option<&'static [u8]> {
        match &entry.handle {
            Handle::File(file) if !entry.path_only && entry.read_allowed => {
                self.backend.get_static_backing_data(file)
            }
            Handle::File(_) | Handle::Dir(_) => None,
        }
    }

    /// Returns the host shared object holding an open file's contents, for a `MAP_SHARED`
    /// mapping, and whether it may be mapped writable.
    ///
    /// The file must be open for reading, and the object may be mapped writable exactly when the
    /// file is open for writing too, as Linux allows of a shared mapping that `mprotect` may
    /// later make writable.
    ///
    /// On a resolver built with [`Self::with_credentials`], the object may never be mapped
    /// writable: stores through a mapping change contents without the resolver, so nothing would
    /// remove the elevation grants (see [`Self::write_as`]) that the file has or gains later.
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
            writable: entry.write_allowed && self.profile.is_none(),
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

impl<Backend: super::backend::Backend> ResolverEntry<Backend> {
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
