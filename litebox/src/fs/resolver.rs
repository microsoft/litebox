// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest filesystem facade backed directly by the broker-core filesystem engine.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use litebox_broker_core::fs as broker_fs;
use litebox_broker_core::fs::backend::DeviceIo;
use litebox_broker_core::fs::resolver::{Engine, ResolverEntry};

use crate::path::Arg;
use crate::{LiteBox, fd::TypedFd, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo};

/// The guest-facing filesystem entry point.
pub struct Resolver<
    Platform: sync::RawSyncPrimitivesProvider,
    Backend: broker_fs::backend::Backend + 'static,
> {
    litebox: LiteBox<Platform>,
    engine: Engine<Backend>,
}

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: broker_fs::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
    /// Construct a new resolver over `backend`.
    #[must_use]
    pub fn new(litebox: &LiteBox<Platform>, backend: Backend) -> Self {
        Self {
            litebox: litebox.clone(),
            engine: Engine::new(backend),
        }
    }
}

impl<Platform: sync::RawSyncPrimitivesProvider> DeviceIo for LiteBox<Platform> {
    fn read_stdin(&self, output: &mut [u8]) -> Result<usize, broker_fs::errors::ReadError> {
        LiteBox::read_stdio(self, output).map_err(|_| broker_fs::errors::ReadError::Io)
    }

    fn write_stdio(
        &self,
        stream: litebox_broker_protocol::stdio::StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, broker_fs::errors::WriteError> {
        LiteBox::write_stdio(self, stream, input).map_err(|_| broker_fs::errors::WriteError::Io)
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), broker_fs::errors::ReadError> {
        LiteBox::fill_random(self, output).map_err(|_| broker_fs::errors::ReadError::Io)
    }
}

/// Per-call resolution context. The user may hold and mutate this as they wish.
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

impl<Platform: sync::RawSyncPrimitivesProvider, Backend: broker_fs::backend::Backend + 'static>
    Resolver<Platform, Backend>
{
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
        let entry = self
            .engine
            .open(
                broker_user_info(context.acting_user()),
                &path,
                broker_open_flags(flags),
                broker_mode(mode),
            )
            .map_err(guest_open_error)?;
        Ok(self.litebox.descriptor_table_mut().insert(entry))
    }

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    pub fn close(&self, fd: &TypedFd<Self>) -> Result<(), CloseError> {
        let mut descriptors = self.litebox.descriptor_table_mut();
        let removed = descriptors.remove(fd);
        drop(descriptors);
        // Some backends might block while closing an fd, so release the descriptor-table lock
        // before dropping the backend handle.
        drop(removed);
        Ok(())
    }

    /// Read from a file descriptor at `offset` into a buffer.
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
        // XXX(jayb): This deliberately preserves the current descriptor-entry lock across backend
        // I/O. A later PR can introduce a smaller position/append serialization primitive.
        self.engine
            .read(&self.litebox, &mut entry.entry, buf, offset)
            .map_err(guest_read_error)
    }

    /// Write from a buffer to a file descriptor at `offset`.
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
        // XXX(jayb): This deliberately preserves the current descriptor-entry lock across backend
        // I/O. A later PR can introduce a smaller position/append serialization primitive.
        self.engine
            .write(&self.litebox, &mut entry.entry, buf, offset)
            .map_err(guest_write_error)
    }

    /// Reposition the read/write file offset, by changing it to `offset` relative to `whence`.
    ///
    /// Returns the resulting offset (in bytes from start of file) on success.
    pub fn seek(
        &self,
        fd: &TypedFd<Self>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(SeekError::ClosedFd)?;
        let mut entry = entry.get_entry_mut();
        self.engine
            .seek(&mut entry.entry, offset, broker_seek_whence(whence))
            .map_err(guest_seek_error)
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
        self.engine
            .truncate(&mut entry.entry, length, reset_offset)
            .map_err(guest_truncate_error)
    }

    /// Change the permissions of a file.
    pub fn chmod(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), ChmodError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .chmod(
                broker_user_info(context.acting_user()),
                &path,
                broker_mode(mode),
            )
            .map_err(guest_chmod_error)
    }

    /// Change the owner of a file.
    pub fn chown(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .chown(broker_user_info(context.acting_user()), &path, user, group)
            .map_err(guest_chown_error)
    }

    /// Unlink a file.
    pub fn unlink(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .unlink(broker_user_info(context.acting_user()), &path)
            .map_err(guest_unlink_error)
    }

    /// Create a new directory.
    pub fn mkdir(&self, context: &Context, path: impl Arg, mode: Mode) -> Result<(), MkdirError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .mkdir(
                broker_user_info(context.acting_user()),
                &path,
                broker_mode(mode),
            )
            .map_err(guest_mkdir_error)
    }

    /// Remove a directory.
    pub fn rmdir(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .rmdir(broker_user_info(context.acting_user()), &path)
            .map_err(guest_rmdir_error)
    }

    /// Read directory entries from a directory file descriptor.
    ///
    /// Returns a list of file/directory names including synthesized `.` and `..` entries.
    pub fn read_dir(&self, fd: &TypedFd<Self>) -> Result<Vec<DirEntry>, ReadDirError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(ReadDirError::ClosedFd)?;
        let entry = entry.get_entry();
        self.engine
            .read_dir(&entry.entry)
            .map_err(guest_read_dir_error)
            .map(guest_directory_entries)
    }

    /// Obtain the status of a path.
    pub fn file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<FileStatus, FileStatusError> {
        let path = context.resolve(path)?.to_string();
        self.engine
            .file_status(broker_user_info(context.acting_user()), &path)
            .map_err(guest_file_status_error)
            .map(guest_file_status)
    }

    /// Equivalent to [`Self::file_status`], but on an open `fd`.
    pub fn fd_file_status(&self, fd: &TypedFd<Self>) -> Result<FileStatus, FileStatusError> {
        let entry = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(FileStatusError::ClosedFd)?;
        let entry = entry.get_entry();
        self.engine
            .handle_status(&entry.entry)
            .map_err(guest_file_status_error)
            .map(guest_file_status)
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
        self.engine.get_static_backing_data(&entry.entry)
    }
}

// TODO: Remove most of the guest/core conversion helpers below once LiteBox uses the broker file
// APIs exclusively. They temporarily preserve LiteBox's guest-facing types while this facade calls
// the broker-core engine directly.
fn broker_mode(mode: Mode) -> broker_fs::Mode {
    broker_fs::Mode::from_bits_retain(mode.bits())
}

fn guest_mode(mode: broker_fs::Mode) -> Mode {
    Mode::from_bits_retain(mode.bits())
}

fn broker_open_flags(flags: OFlags) -> broker_fs::OFlags {
    broker_fs::OFlags::from_bits_retain(flags.bits())
}

fn broker_user_info(user: UserInfo) -> broker_fs::UserInfo {
    broker_fs::UserInfo {
        user: user.user,
        group: user.group,
    }
}

fn guest_user_info(user: broker_fs::UserInfo) -> UserInfo {
    UserInfo {
        user: user.user,
        group: user.group,
    }
}

fn broker_seek_whence(whence: SeekWhence) -> broker_fs::SeekWhence {
    match whence {
        SeekWhence::RelativeToBeginning => broker_fs::SeekWhence::RelativeToBeginning,
        SeekWhence::RelativeToCurrentOffset => broker_fs::SeekWhence::RelativeToCurrentOffset,
        SeekWhence::RelativeToEnd => broker_fs::SeekWhence::RelativeToEnd,
    }
}

fn guest_file_type(file_type: broker_fs::FileType) -> FileType {
    match file_type {
        broker_fs::FileType::RegularFile => FileType::RegularFile,
        broker_fs::FileType::Directory => FileType::Directory,
        broker_fs::FileType::CharacterDevice => FileType::CharacterDevice,
    }
}

fn guest_node_info(node: broker_fs::NodeInfo) -> NodeInfo {
    NodeInfo {
        dev: node.dev,
        ino: node.ino,
        rdev: node.rdev,
    }
}

fn guest_file_status(status: broker_fs::FileStatus) -> FileStatus {
    FileStatus {
        file_type: guest_file_type(status.file_type),
        mode: guest_mode(status.mode),
        size: status.size,
        owner: guest_user_info(status.owner),
        node_info: guest_node_info(status.node_info),
        blksize: status.blksize,
    }
}

fn guest_directory_entries(entries: Vec<broker_fs::DirEntry>) -> Vec<DirEntry> {
    entries
        .into_iter()
        .map(|entry| DirEntry {
            name: entry.name,
            file_type: guest_file_type(entry.file_type),
            ino_info: entry.ino_info.map(guest_node_info),
        })
        .collect()
}

fn guest_path_error(error: broker_fs::errors::PathError) -> PathError {
    match error {
        broker_fs::errors::PathError::NoSuchFileOrDirectory => PathError::NoSuchFileOrDirectory,
        broker_fs::errors::PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir,
            #[cfg(debug_assertions)]
            perms,
        } => PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir,
            #[cfg(debug_assertions)]
            perms: guest_mode(perms),
        },
        broker_fs::errors::PathError::InvalidPathname => PathError::InvalidPathname,
        broker_fs::errors::PathError::MissingComponent => PathError::MissingComponent,
        broker_fs::errors::PathError::ComponentNotADirectory => PathError::ComponentNotADirectory,
    }
}

fn guest_open_error(error: broker_fs::errors::OpenError) -> OpenError {
    match error {
        broker_fs::errors::OpenError::AccessNotAllowed => OpenError::AccessNotAllowed,
        broker_fs::errors::OpenError::NoWritePerms => OpenError::NoWritePerms,
        broker_fs::errors::OpenError::ReadOnlyFileSystem => OpenError::ReadOnlyFileSystem,
        broker_fs::errors::OpenError::AlreadyExists => OpenError::AlreadyExists,
        broker_fs::errors::OpenError::TruncateError(error) => {
            OpenError::TruncateError(guest_truncate_error(error))
        }
        broker_fs::errors::OpenError::Io => OpenError::Io,
        broker_fs::errors::OpenError::PathError(error) => {
            OpenError::PathError(guest_path_error(error))
        }
    }
}

fn guest_read_error(error: broker_fs::errors::ReadError) -> ReadError {
    match error {
        broker_fs::errors::ReadError::ClosedFd => ReadError::ClosedFd,
        broker_fs::errors::ReadError::NotAFile => ReadError::NotAFile,
        broker_fs::errors::ReadError::NotForReading => ReadError::NotForReading,
        broker_fs::errors::ReadError::Io => ReadError::Io,
    }
}

fn guest_write_error(error: broker_fs::errors::WriteError) -> WriteError {
    match error {
        broker_fs::errors::WriteError::ClosedFd => WriteError::ClosedFd,
        broker_fs::errors::WriteError::NotAFile => WriteError::NotAFile,
        broker_fs::errors::WriteError::NotForWriting => WriteError::NotForWriting,
        broker_fs::errors::WriteError::Io => WriteError::Io,
    }
}

fn guest_seek_error(error: broker_fs::errors::SeekError) -> SeekError {
    match error {
        broker_fs::errors::SeekError::ClosedFd => SeekError::ClosedFd,
        broker_fs::errors::SeekError::NotAFile => SeekError::NotAFile,
        broker_fs::errors::SeekError::InvalidOffset => SeekError::InvalidOffset,
        broker_fs::errors::SeekError::NonSeekable => SeekError::NonSeekable,
        broker_fs::errors::SeekError::Io => SeekError::Io,
    }
}

fn guest_truncate_error(error: broker_fs::errors::TruncateError) -> TruncateError {
    match error {
        broker_fs::errors::TruncateError::ClosedFd => TruncateError::ClosedFd,
        broker_fs::errors::TruncateError::IsDirectory => TruncateError::IsDirectory,
        broker_fs::errors::TruncateError::NotForWriting => TruncateError::NotForWriting,
        broker_fs::errors::TruncateError::IsTerminalDevice => TruncateError::IsTerminalDevice,
        broker_fs::errors::TruncateError::Io => TruncateError::Io,
    }
}

fn guest_chmod_error(error: broker_fs::errors::ChmodError) -> ChmodError {
    match error {
        broker_fs::errors::ChmodError::NotTheOwner => ChmodError::NotTheOwner,
        broker_fs::errors::ChmodError::ReadOnlyFileSystem => ChmodError::ReadOnlyFileSystem,
        broker_fs::errors::ChmodError::Io => ChmodError::Io,
        broker_fs::errors::ChmodError::PathError(error) => {
            ChmodError::PathError(guest_path_error(error))
        }
    }
}

fn guest_chown_error(error: broker_fs::errors::ChownError) -> ChownError {
    match error {
        broker_fs::errors::ChownError::NotTheOwner => ChownError::NotTheOwner,
        broker_fs::errors::ChownError::ReadOnlyFileSystem => ChownError::ReadOnlyFileSystem,
        broker_fs::errors::ChownError::Io => ChownError::Io,
        broker_fs::errors::ChownError::PathError(error) => {
            ChownError::PathError(guest_path_error(error))
        }
    }
}

fn guest_unlink_error(error: broker_fs::errors::UnlinkError) -> UnlinkError {
    match error {
        broker_fs::errors::UnlinkError::NoWritePerms => UnlinkError::NoWritePerms,
        broker_fs::errors::UnlinkError::IsADirectory => UnlinkError::IsADirectory,
        broker_fs::errors::UnlinkError::ReadOnlyFileSystem => UnlinkError::ReadOnlyFileSystem,
        broker_fs::errors::UnlinkError::Io => UnlinkError::Io,
        broker_fs::errors::UnlinkError::PathError(error) => {
            UnlinkError::PathError(guest_path_error(error))
        }
    }
}

fn guest_mkdir_error(error: broker_fs::errors::MkdirError) -> MkdirError {
    match error {
        broker_fs::errors::MkdirError::NoWritePerms => MkdirError::NoWritePerms,
        broker_fs::errors::MkdirError::AlreadyExists => MkdirError::AlreadyExists,
        broker_fs::errors::MkdirError::ReadOnlyFileSystem => MkdirError::ReadOnlyFileSystem,
        broker_fs::errors::MkdirError::Io => MkdirError::Io,
        broker_fs::errors::MkdirError::PathError(error) => {
            MkdirError::PathError(guest_path_error(error))
        }
    }
}

fn guest_rmdir_error(error: broker_fs::errors::RmdirError) -> RmdirError {
    match error {
        broker_fs::errors::RmdirError::NoWritePerms => RmdirError::NoWritePerms,
        broker_fs::errors::RmdirError::Busy => RmdirError::Busy,
        broker_fs::errors::RmdirError::NotEmpty => RmdirError::NotEmpty,
        broker_fs::errors::RmdirError::NotADirectory => RmdirError::NotADirectory,
        broker_fs::errors::RmdirError::ReadOnlyFileSystem => RmdirError::ReadOnlyFileSystem,
        broker_fs::errors::RmdirError::Io => RmdirError::Io,
        broker_fs::errors::RmdirError::PathError(error) => {
            RmdirError::PathError(guest_path_error(error))
        }
    }
}

fn guest_read_dir_error(error: broker_fs::errors::ReadDirError) -> ReadDirError {
    match error {
        broker_fs::errors::ReadDirError::ClosedFd => ReadDirError::ClosedFd,
        broker_fs::errors::ReadDirError::NotADirectory => ReadDirError::NotADirectory,
        broker_fs::errors::ReadDirError::Io => ReadDirError::Io,
    }
}

fn guest_file_status_error(error: broker_fs::errors::FileStatusError) -> FileStatusError {
    match error {
        broker_fs::errors::FileStatusError::ClosedFd => FileStatusError::ClosedFd,
        broker_fs::errors::FileStatusError::Io => FileStatusError::Io,
        broker_fs::errors::FileStatusError::PathError(error) => {
            FileStatusError::PathError(guest_path_error(error))
        }
    }
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider }, Backend: { broker_fs::backend::Backend + 'static };
    Resolver<Platform, Backend>;
    @ Backend: { broker_fs::backend::Backend + 'static };
    ResolverEntry<Backend>;
    -> ResolverFd<Platform, Backend>;
}
