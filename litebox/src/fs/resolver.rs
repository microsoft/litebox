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
    backend::{PermissionInfo, SeekBehavior, WalkOutcome},
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
    fn components(&self) -> Vec<&str> {
        self.components.iter().map(String::as_str).collect()
    }

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
        &'a self,
        context: &Context,
        path: &'a ResolvedPath,
    ) -> Result<Option<(Backend::WalkingDirHandle<'a>, &'a str)>, WalkError> {
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

    fn walk_to_directory<'a>(
        &'a self,
        context: &Context,
        from: Backend::WalkingDirHandle<'a>,
        components: &[&str],
        #[cfg(debug_assertions)] absolute_components: &[&str],
    ) -> Result<Backend::WalkingDirHandle<'a>, WalkError> {
        if components.is_empty() {
            return Ok(from);
        }

        let outcome = self.backend.walk_directories(from, components)?;
        Self::check_walk_permissions(
            context,
            #[cfg(debug_assertions)]
            absolute_components,
            &outcome,
        )?;

        if outcome.components.len() != components.len() {
            // TODO(jayb): Continue walking from `outcome.last` once backends can return partial walks.
            unimplemented!("partial backend walks are not supported yet");
        }

        Ok(outcome.last)
    }

    fn check_walk_permissions(
        context: &Context,
        #[cfg(debug_assertions)] absolute_components: &[&str],
        outcome: &WalkOutcome<Backend::WalkingDirHandle<'_>>,
    ) -> Result<(), PathError> {
        for (idx, walked) in outcome.components.iter().enumerate() {
            let Some(permissions) = &walked.permissions else {
                continue;
            };
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
        Ok(())
    }
}

/// This exists purely as a migration feature, until we have completely separated contexts. See
/// comment on `Resolver`.
fn default_context_pre_context_management_changes() -> Context {
    Context::new()
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

        let context = default_context_pre_context_management_changes();
        let path = context.resolve(path)?;
        let access_mode = flags & (OFlags::WRONLY | OFlags::RDWR);
        let read_allowed = access_mode == OFlags::RDONLY || access_mode == OFlags::RDWR;
        let write_allowed = access_mode == OFlags::WRONLY || access_mode == OFlags::RDWR;
        let append_mode = flags.contains(OFlags::APPEND);
        let insert = |handle, seek_behavior| {
            self.litebox.descriptor_table_mut().insert(ResolverEntry {
                handle,
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
                OwnedHandle::Dir(self.backend.owned_dir_at(self.backend.root())),
                SeekBehavior::NonSeekable,
            ));
        }

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
        let parent = self.backend.owned_dir_at(parent);

        let walking_parent = self.backend.walking_dir_at(&parent).ok_or(OpenError::Io)?;
        match self.backend.open_file_at(walking_parent, name, flags) {
            Ok(file) => {
                if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                    return Err(OpenError::AlreadyExists);
                }
                let seek_behavior = self.backend.seek_behavior(&file);
                Ok(insert(OwnedHandle::File(file), seek_behavior))
            }
            Err(
                error @ OpenError::PathError(
                    PathError::NoSuchFileOrDirectory | PathError::ComponentNotADirectory,
                ),
            ) => {
                let walking_parent = self.backend.walking_dir_at(&parent).ok_or(OpenError::Io)?;
                match self.walk_to_directory(
                    &context,
                    walking_parent,
                    &[name],
                    #[cfg(debug_assertions)]
                    &path.components(),
                ) {
                    Ok(dir) => {
                        if flags.contains(OFlags::CREAT) && flags.contains(OFlags::EXCL) {
                            return Err(OpenError::AlreadyExists);
                        }
                        Ok(insert(
                            OwnedHandle::Dir(self.backend.owned_dir_at(dir)),
                            SeekBehavior::NonSeekable,
                        ))
                    }
                    Err(_) if flags.contains(OFlags::CREAT) => match error {
                        OpenError::PathError(PathError::NoSuchFileOrDirectory) => {
                            let file = self.backend.create_file_at(parent, name, mode)?;
                            let seek_behavior = self.backend.seek_behavior(&file);
                            Ok(insert(OwnedHandle::File(file), seek_behavior))
                        }
                        _ => Err(error),
                    },
                    Err(_) => Err(error),
                }
            }
            Err(error) => Err(error),
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
        let table = self.litebox.descriptor_table();
        let mut entry = table.get_entry_mut(fd).ok_or(ReadError::ClosedFd)?;
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(ReadError::NotAFile),
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
        let table = self.litebox.descriptor_table();
        let mut entry = table.get_entry_mut(fd).ok_or(WriteError::ClosedFd)?;
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(WriteError::NotAFile),
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
        let table = self.litebox.descriptor_table();
        let mut entry = table.get_entry_mut(fd).ok_or(SeekError::ClosedFd)?;
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(SeekError::NotAFile),
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
        let table = self.litebox.descriptor_table();
        let mut entry = table.get_entry_mut(fd).ok_or(TruncateError::ClosedFd)?;
        let file = match &entry.entry.handle {
            OwnedHandle::File(file) => file,
            OwnedHandle::Dir(_) => return Err(TruncateError::IsDirectory),
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
        let context = default_context_pre_context_management_changes();
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
        self.backend
            .chmod_at(self.backend.owned_dir_at(parent), name, mode)
    }

    fn chown(
        &self,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let context = default_context_pre_context_management_changes();
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
        self.backend
            .chown_at(self.backend.owned_dir_at(parent), name, user, group)
    }

    fn unlink(&self, path: impl Arg) -> Result<(), UnlinkError> {
        let context = default_context_pre_context_management_changes();
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
        self.backend
            .unlink_at(self.backend.owned_dir_at(parent), name)
    }

    fn mkdir(&self, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        let context = default_context_pre_context_management_changes();
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
        self.backend
            .mkdir_at(self.backend.owned_dir_at(parent), name, mode)
            .map(|_| ())
    }

    fn rmdir(&self, path: impl Arg) -> Result<(), RmdirError> {
        let context = default_context_pre_context_management_changes();
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
        self.backend
            .rmdir_at(self.backend.owned_dir_at(parent), name)
    }

    fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let table = self.litebox.descriptor_table();
        let entry = table.get_entry(fd).ok_or(ReadDirError::ClosedFd)?;
        if entry.entry.path_only {
            // TODO(jayb): Add an error variant for operations not permitted on O_PATH fds.
            unimplemented!("read_dir on O_PATH fd")
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

    fn file_status(&self, path: impl Arg) -> Result<super::FileStatus, FileStatusError> {
        // TODO(jayb): Improve this. Opening just to stat forces the resolver to choose open flags,
        // but stat itself should be access-neutral.
        let fd = self
            .open(path, OFlags::RDONLY, Mode::empty())
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
        let table = self.litebox.descriptor_table();
        let entry = table.get_entry(fd).ok_or(FileStatusError::ClosedFd)?;
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.file_status(file),
            OwnedHandle::Dir(dir) => self.backend.dir_status(dir),
        }
    }

    fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        let table = self.litebox.descriptor_table();
        let entry = table.get_entry(fd)?;
        match &entry.entry.handle {
            OwnedHandle::File(file) => self.backend.get_static_backing_data(file),
            OwnedHandle::Dir(_) => None,
        }
    }
}

/// A file or a directory handle
enum OwnedHandle<Backend: super::backend::Backend> {
    File(Backend::FileHandle),
    Dir(Backend::DirHandle),
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "resolver fd entries carry independent descriptor flags"
)]
struct ResolverEntry<Backend: super::backend::Backend> {
    handle: OwnedHandle<Backend>,
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
