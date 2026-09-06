// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest filesystem facade backed by broker filesystem objects.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};
use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    FilesystemDirectoryEntry, FilesystemError, FilesystemFileStatus, FilesystemFileType,
    FilesystemNamespace, FilesystemNodeInfo, FilesystemSeekWhence, FilesystemUser,
};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::{FileType, Mode, OFlags, UserInfo};

/// The guest-facing filesystem entry point.
pub struct Resolver<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    authority: ResolverAuthority,
}

/// The broker connection and namespace backing a [`Resolver`]'s filesystem operations.
struct ResolverAuthority {
    broker: Arc<dyn crate::broker::BrokerControl>,
    namespace: FilesystemNamespace,
}

impl<Platform: sync::RawSyncPrimitivesProvider> Resolver<Platform> {
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
            authority: ResolverAuthority {
                broker: litebox
                    .broker_control()
                    .expect("brokered filesystem requires a broker connection"),
                namespace,
            },
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
impl<Platform: sync::RawSyncPrimitivesProvider> Resolver<Platform> {
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
        let path = context.resolve(path)?.to_string();
        let handle = self
            .authority
            .broker
            .open_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
                flags.bits(),
                mode.bits(),
            )
            .map_err(|_| OpenError::Io)?
            .map_err(open_error)?;
        let description = ResolverDescription {
            inner: BrokerOpenFileDescription(Arc::new(BrokerOpenFileDescriptionInner {
                broker: Arc::clone(&self.authority.broker),
                handle,
            })),
            _platform: core::marker::PhantomData,
        };
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert(ResolverEntry { description }))
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
        description
            .inner
            .broker
            .read_file(
                description.inner.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ReadError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, ReadError::ClosedFd, ReadError::Io))?
            .map_err(read_error)
    }

    /// Writes to `fd`, optionally at an explicit offset.
    pub fn write(
        &self,
        fd: &TypedFd<Self>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let description = self.open_file_description(fd).ok_or(WriteError::ClosedFd)?;
        description
            .inner
            .broker
            .write_file(
                description.inner.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| WriteError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, WriteError::ClosedFd, WriteError::Io))?
            .map_err(write_error)
    }

    /// Repositions the shared offset of `fd`.
    pub fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: super::SeekWhence,
    ) -> Result<usize, SeekError> {
        let description = self.open_file_description(fd).ok_or(SeekError::ClosedFd)?;
        let offset = i64::try_from(offset).map_err(|_| SeekError::InvalidOffset)?;
        let offset = description
            .inner
            .broker
            .seek_file(description.inner.handle, offset, fs_seek_whence(whence))
            .map_err(|error| broker_fd_error(error, SeekError::ClosedFd, SeekError::Io))?
            .map_err(seek_error)?;
        usize::try_from(offset).map_err(|_| SeekError::InvalidOffset)
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
        description
            .inner
            .broker
            .truncate_file(
                description.inner.handle,
                u64::try_from(length).map_err(|_| TruncateError::Io)?,
                reset_offset,
            )
            .map_err(|error| broker_fd_error(error, TruncateError::ClosedFd, TruncateError::Io))?
            .map_err(truncate_error)
    }

    /// Changes the permissions of a file.
    pub fn chmod(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = context.resolve(path)?.to_string();
        self.authority
            .broker
            .chmod_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
                mode.bits(),
            )
            .map_err(|_| ChmodError::Io)?
            .map_err(chmod_error)
    }

    /// Changes the owner of a file.
    pub fn chown(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = context.resolve(path)?.to_string();
        self.authority
            .broker
            .chown_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
                user,
                group,
            )
            .map_err(|_| ChownError::Io)?
            .map_err(chown_error)
    }

    /// Unlinks a file.
    pub fn unlink(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        let path = context.resolve(path)?.to_string();
        self.authority
            .broker
            .unlink_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
            )
            .map_err(|_| UnlinkError::Io)?
            .map_err(unlink_error)
    }

    /// Creates a directory.
    pub fn mkdir(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        let path = context.resolve(path)?.to_string();
        self.authority
            .broker
            .mkdir_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
                mode.bits(),
            )
            .map_err(|_| MkdirError::Io)?
            .map_err(mkdir_error)
    }

    /// Removes a directory.
    pub fn rmdir(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        let path = context.resolve(path)?.to_string();
        self.authority
            .broker
            .rmdir_file(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
            )
            .map_err(|_| RmdirError::Io)?
            .map_err(rmdir_error)
    }

    /// Reads directory entries from an open directory descriptor.
    pub fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<super::DirEntry>, ReadDirError> {
        let description = self
            .open_file_description(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        let entries = description
            .inner
            .broker
            .read_directory(description.inner.handle)
            .map_err(|error| broker_fd_error(error, ReadDirError::ClosedFd, ReadDirError::Io))?
            .map_err(read_dir_error)?;
        directory_entries(entries)
    }

    /// Obtains the status of the object named by `path`.
    pub fn file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<super::FileStatus, FileStatusError> {
        let path = context.resolve(path)?.to_string();
        let status = self
            .authority
            .broker
            .path_file_status(
                self.authority.namespace,
                &path,
                fs_user(context.acting_user()),
            )
            .map_err(|_| FileStatusError::Io)?
            .map_err(file_status_error)?;
        file_status(status)
    }

    /// Obtains the status of the object referenced by `fd`.
    pub fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<super::FileStatus, FileStatusError> {
        let description = self
            .open_file_description(fd)
            .ok_or(FileStatusError::ClosedFd)?;
        let status = description
            .inner
            .broker
            .handle_file_status(description.inner.handle)
            .map_err(|error| {
                broker_fd_error(error, FileStatusError::ClosedFd, FileStatusError::Io)
            })?
            .map_err(file_status_error)?;
        file_status(status)
    }

    /// Gets static backing data for a file, if available.
    pub fn get_static_backing_data(&self, fd: &TypedFd<Self>) -> Option<&'static [u8]> {
        let _description = self.open_file_description(fd)?;
        // TODO: Restore zero-copy backing after broker shared-memory objects are available.
        None
    }
}

struct ResolverEntry<Platform: sync::RawSyncPrimitivesProvider> {
    description: ResolverDescription<Platform>,
}

/// A broker-backed open file description, tagged with the guest `Platform` for FD typing.
struct ResolverDescription<Platform: sync::RawSyncPrimitivesProvider> {
    inner: BrokerOpenFileDescription,
    _platform: core::marker::PhantomData<fn() -> Platform>,
}

impl<Platform: sync::RawSyncPrimitivesProvider> Clone for ResolverDescription<Platform> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            _platform: core::marker::PhantomData,
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

const fn fs_user(user: UserInfo) -> FilesystemUser {
    FilesystemUser {
        user: user.user,
        group: user.group,
    }
}

const fn fs_seek_whence(whence: super::SeekWhence) -> FilesystemSeekWhence {
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
    @ Platform: { sync::RawSyncPrimitivesProvider };
    Resolver<Platform>;
    @ Platform: { sync::RawSyncPrimitivesProvider };
    ResolverEntry<Platform>;
    -> ResolverFd<Platform>;
}
