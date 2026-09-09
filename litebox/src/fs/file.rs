// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Guest file operations backed by broker-owned file objects.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use bitflags::bitflags;
use core::ffi::c_uint;
use core::num::NonZeroUsize;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileDirectoryEntry, FileError, FileMode, FileNodeInfo, FileOpenFlags,
    FileSeekWhence, FileStatus as BrokerFileStatus, FileType, FileUser,
};

use crate::path::Arg;
use crate::{LiteBox, sync};

use super::errors::{
    ChmodError, ChownError, CloseError, FileStatusError, MkdirError, OpenError, PathError,
    ReadDirError, ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};

bitflags! {
    /// `S_I*` constants for open, ...
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct Mode: c_uint {
        /// `S_IRWXU`: user (file owner) has read, write, and execute permission
        const RWXU = 0o00700;
        /// `S_IRUSR`: user has read permission
        const RUSR = 0o00400;
        /// `S_IWUSR`: user has write permission
        const WUSR = 0o00200;
        /// `S_IXUSR`: user has execute permission
        const XUSR = 0o00100;
        /// `S_IRWXG`: group has read, write, and execute permission
        const RWXG = 0o00070;
        /// `S_IRGRP`: group has read permission
        const RGRP = 0o00040;
        /// `S_IWGRP`: group has write permission
        const WGRP = 0o00020;
        /// `S_IXGRP`: group has execute permission
        const XGRP = 0o00010;
        /// `S_IRWXO`: others have read, write, and execute permission
        const RWXO = 0o00007;
        /// `S_IROTH`: others have read permission
        const ROTH = 0o00004;
        /// `S_IWOTH`: others have write permission
        const WOTH = 0o00002;
        /// `S_IXOTH`: others have execute permission
        const XOTH = 0o00001;
        /// `S_ISUID`: set-user-ID bit
        const SUID = 0o0004000;
        /// `S_ISGID`: set-group-ID bit (see inode(7)).
        const SGID = 0o0002000;
        /// `S_ISVTX`: sticky bit (see inode(7)).
        const SVTX = 0o0001000;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;
    }
}

bitflags! {
    /// `O_*` constants for use with open, ...
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct OFlags: c_uint {
        /// `O_RDONLY`: read-only
        const RDONLY = 0x0;
        /// `O_WRONLY`: write-only
        const WRONLY = 0x1;
        /// `O_RDWR`: read/write.
        ///
        /// This is not equal to `RDONLY | WRONLY`. It's a distinct flag.
        const RDWR = 0x2;
        /// `O_APPEND`: append mode
        const APPEND = 0x400;
        /// `O_ASYNC`: signal-driven I/O
        const ASYNC = 0x2000;
        /// `O_CLOEXEC`: close-on-exec flag
        const CLOEXEC = 0x80000;
        /// `O_CREAT`: if path does not exist, create it as a regular file
        const CREAT = 0x40;
        /// `O_DIRECT`: try to minimize cache effects of I/O
        #[cfg(target_arch = "x86_64")]
        const DIRECT = 0x4000;
        #[cfg(target_arch = "aarch64")]
        const DIRECT = 0x10000;
        /// `O_DIRECTORY`: fail if not a directory
        #[cfg(target_arch = "x86_64")]
        const DIRECTORY = 0x10000;
        #[cfg(target_arch = "aarch64")]
        const DIRECTORY = 0x4000;
        /// `O_DSYNC`: write operations on the file will complete according to the requirements of
        /// synchronized I/O *data* integrity completion.
        const DSYNC = 0x1000;
        /// `O_EXCL`: exclusive use
        const EXCL = 0x80;
        /// `O_LARGEFILE`: allow large file support
        #[cfg(target_arch = "x86_64")]
        const LARGEFILE = 0x8000;
        #[cfg(target_arch = "aarch64")]
        const LARGEFILE = 0x20000;
        /// `O_NOATIME`: do not update access time
        const NOATIME = 0x40000;
        /// `O_NOCTTY`: do not assign controlling terminal
        const NOCTTY = 0x100;
        /// `O_NOFOLLOW`: fail if the path does not point to a regular file
        #[cfg(target_arch = "x86_64")]
        const NOFOLLOW = 0x20000;
        #[cfg(target_arch = "aarch64")]
        const NOFOLLOW = 0x8000;
        /// `O_NDELAY`: non-blocking mode (same as NONBLOCK)
        const NDELAY = 0x800;
        /// `O_NONBLOCK`: non-blocking mode (same as NDELAY)
        const NONBLOCK = 0x800;
        /// `O_PATH`: open a file descriptor for path resolution only
        const PATH = 0x200000;
        /// `O_SYNC`: write operations on the file will complete according to the requirements of
        /// synchronized I/O file integrity completion (by contrast with the synchronized I/O data
        /// integrity completion provided by `O_DSYNC`.)
        const SYNC = 0x101000;
        /// `O_TMPFILE`: create an unnamed temporary file
        #[cfg(target_arch = "x86_64")]
        const TMPFILE = 0x410000;
        #[cfg(target_arch = "aarch64")]
        const TMPFILE = 0x404000;
        /// `O_TRUNC`: truncate the file to zero length
        const TRUNC = 0x200;
        /// <https://docs.rs/bitflags/*/bitflags/#externally-defined-flags>
        const _ = !0;

        /// All file status flags + access modes
        const STATUS_FLAGS_MASK = Self::APPEND.bits()
            | Self::NONBLOCK.bits()
            | Self::DSYNC.bits()
            | Self::ASYNC.bits()
            | Self::DIRECT.bits()
            | Self::LARGEFILE.bits()
            | Self::NOATIME.bits()
            | Self::SYNC.bits()
            | Self::PATH.bits()
            | Self::RDONLY.bits()
            | Self::WRONLY.bits()
            | Self::RDWR.bits();
    }
}

/// The `whence` directive to [`LiteBox::seek_file`].
#[derive(Copy, Clone)]
pub enum SeekWhence {
    /// The file offset is set to `offset` bytes.
    RelativeToBeginning,
    /// The file offset is set to its current location plus `offset` bytes.
    RelativeToCurrentOffset,
    /// The file offset is set to the size of the file plus `offset` bytes.
    RelativeToEnd,
}

/// The status of a file/directory/... on the file-system, inspired by `stat(3type)`.
///
/// This is explicitly a non-exhaustive struct with public members. As LiteBox evolves, more
/// elements might be added to this struct, allowing file systems to provide richer information
/// about the status of files. However, users of LiteBox must not depend on the completeness or even
/// layout of this particular type.
#[non_exhaustive]
pub struct FileStatus {
    /// File type
    pub file_type: FileType,
    /// Permissions for the file
    pub mode: Mode,
    /// Size of the file, in bytes. This value considered informative if this is a regular file.
    pub size: usize,
    /// Owner of the file
    pub owner: UserInfo,
    /// Information about this particular node
    pub node_info: NodeInfo,
    /// Block size for file system I/O
    pub blksize: usize,
}

/// User information
#[derive(Clone, Copy, Debug)]
pub struct UserInfo {
    /// User ID for the owner
    pub user: u16,
    /// Group ID for the owner
    pub group: u16,
}

/// Device/Inode information
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct NodeInfo {
    /// Device number
    pub dev: usize,
    /// Inode number
    pub ino: usize,
    /// Device that is being referred to (will be `Some(...)` only if special file)
    pub rdev: Option<NonZeroUsize>,
}

/// Directory entries returned by [`LiteBox::read_file_directory`].
#[derive(Debug)]
#[non_exhaustive]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
    pub ino_info: Option<NodeInfo>,
}

impl UserInfo {
    /// The root user
    pub const ROOT: Self = Self { user: 0, group: 0 };
}

/// Type marker for file descriptors backed by broker-owned files.
pub struct File<Platform: sync::RawSyncPrimitivesProvider>(core::marker::PhantomData<fn(Platform)>);

impl<Platform: sync::RawSyncPrimitivesProvider> LiteBox<Platform> {
    fn broker_file(&self, fd: &FileFd<Platform>) -> Option<Arc<BrokerFile>> {
        self.descriptor_table()
            .with_entry(fd, |entry| Arc::clone(&entry.entry))
    }

    fn broker_path(context: &Context, path: impl Arg) -> Result<String, PathError> {
        Ok(context.resolve(path)?.to_string())
    }

    /// Opens a file.
    ///
    /// The `mode` is only significant when creating a file.
    pub fn open_file(
        &self,
        context: &Context,
        path: impl Arg,
        flags: OFlags,
        mode: Mode,
    ) -> Result<FileFd<Platform>, OpenError> {
        let path = Self::broker_path(context, path)?;
        let (access, flags) = file_open_options(flags)?;
        let broker = self.broker_control().ok_or(OpenError::Io)?;
        let handle = broker
            .open_file(
                &path,
                file_user(context.acting_user()),
                access,
                flags,
                file_mode(mode),
            )
            .map_err(|_| OpenError::Io)?
            .map_err(open_error)?;
        Ok(self
            .descriptor_table_mut()
            .insert(Arc::new(BrokerFile { broker, handle })))
    }

    /// Close the file at `fd`.
    ///
    /// Future operations on the `fd` will start to return `ClosedFd` errors.
    pub fn close_file(&self, fd: &FileFd<Platform>) -> Result<(), CloseError> {
        let mut descriptors = self.descriptor_table_mut();
        let removed = descriptors.remove(fd);
        drop(descriptors);
        drop(removed);
        Ok(())
    }

    /// Read from a file descriptor at `offset` into a buffer.
    pub fn read_file(
        &self,
        fd: &FileFd<Platform>,
        buf: &mut [u8],
        offset: Option<usize>,
    ) -> Result<usize, ReadError> {
        let file = self.broker_file(fd).ok_or(ReadError::ClosedFd)?;
        file.broker
            .read_file(
                file.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| ReadError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, ReadError::ClosedFd, ReadError::Io))?
            .map_err(read_error)
    }

    /// Write from a buffer to a file descriptor at `offset`.
    pub fn write_file(
        &self,
        fd: &FileFd<Platform>,
        buf: &[u8],
        offset: Option<usize>,
    ) -> Result<usize, WriteError> {
        let file = self.broker_file(fd).ok_or(WriteError::ClosedFd)?;
        file.broker
            .write_file(
                file.handle,
                buf,
                offset
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| WriteError::Io)?,
            )
            .map_err(|error| broker_fd_error(error, WriteError::ClosedFd, WriteError::Io))?
            .map_err(write_error)
    }

    /// Reposition the read/write file offset.
    pub fn seek_file(
        &self,
        fd: &FileFd<Platform>,
        offset: isize,
        whence: SeekWhence,
    ) -> Result<usize, SeekError> {
        let file = self.broker_file(fd).ok_or(SeekError::ClosedFd)?;
        let offset = i64::try_from(offset).map_err(|_| SeekError::InvalidOffset)?;
        let offset = file
            .broker
            .seek_file(file.handle, offset, file_seek_whence(whence))
            .map_err(|error| broker_fd_error(error, SeekError::ClosedFd, SeekError::Io))?
            .map_err(seek_error)?;
        usize::try_from(offset).map_err(|_| SeekError::InvalidOffset)
    }

    /// Truncate the file to the specified length.
    pub fn truncate_file(
        &self,
        fd: &FileFd<Platform>,
        length: usize,
        reset_offset: bool,
    ) -> Result<(), TruncateError> {
        let file = self.broker_file(fd).ok_or(TruncateError::ClosedFd)?;
        file.broker
            .truncate_file(
                file.handle,
                u64::try_from(length).map_err(|_| TruncateError::Io)?,
                reset_offset,
            )
            .map_err(|error| broker_fd_error(error, TruncateError::ClosedFd, TruncateError::Io))?
            .map_err(truncate_error)
    }

    /// Change the permissions of a file.
    pub fn chmod_file(
        &self,
        context: &Context,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), ChmodError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(ChmodError::Io)?
            .chmod_file(&path, file_user(context.acting_user()), file_mode(mode))
            .map_err(|_| ChmodError::Io)?
            .map_err(chmod_error)
    }

    /// Change the owner of a file.
    pub fn chown_file(
        &self,
        context: &Context,
        path: impl Arg,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(ChownError::Io)?
            .chown_file(&path, file_user(context.acting_user()), user, group)
            .map_err(|_| ChownError::Io)?
            .map_err(chown_error)
    }

    /// Unlink a file.
    pub fn unlink_file(&self, context: &Context, path: impl Arg) -> Result<(), UnlinkError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(UnlinkError::Io)?
            .unlink_file(&path, file_user(context.acting_user()))
            .map_err(|_| UnlinkError::Io)?
            .map_err(unlink_error)
    }

    /// Create a new directory.
    pub fn mkdir_file(
        &self,
        context: &Context,
        path: impl Arg,
        mode: Mode,
    ) -> Result<(), MkdirError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(MkdirError::Io)?
            .mkdir_file(&path, file_user(context.acting_user()), file_mode(mode))
            .map_err(|_| MkdirError::Io)?
            .map_err(mkdir_error)
    }

    /// Remove a directory.
    pub fn rmdir_file(&self, context: &Context, path: impl Arg) -> Result<(), RmdirError> {
        let path = Self::broker_path(context, path)?;
        self.broker_control()
            .ok_or(RmdirError::Io)?
            .rmdir_file(&path, file_user(context.acting_user()))
            .map_err(|_| RmdirError::Io)?
            .map_err(rmdir_error)
    }

    /// Read directory entries from a directory file descriptor.
    pub fn read_file_directory(
        &self,
        fd: &FileFd<Platform>,
    ) -> Result<Vec<DirEntry>, ReadDirError> {
        let file = self.broker_file(fd).ok_or(ReadDirError::ClosedFd)?;
        let entries = file
            .broker
            .read_directory(file.handle)
            .map_err(|error| broker_fd_error(error, ReadDirError::ClosedFd, ReadDirError::Io))?
            .map_err(read_dir_error)?;
        directory_entries(entries)
    }

    /// Obtain the status of a path.
    pub fn path_file_status(
        &self,
        context: &Context,
        path: impl Arg,
    ) -> Result<FileStatus, FileStatusError> {
        let path = Self::broker_path(context, path)?;
        let status = self
            .broker_control()
            .ok_or(FileStatusError::Io)?
            .path_file_status(&path, file_user(context.acting_user()))
            .map_err(|_| FileStatusError::Io)?
            .map_err(file_status_error)?;
        file_status(status)
    }

    /// Equivalent to [`Self::path_file_status`], but on an open `fd`.
    pub fn file_status(&self, fd: &FileFd<Platform>) -> Result<FileStatus, FileStatusError> {
        let file = self.broker_file(fd).ok_or(FileStatusError::ClosedFd)?;
        let status = file
            .broker
            .handle_file_status(file.handle)
            .map_err(|error| {
                broker_fd_error(error, FileStatusError::ClosedFd, FileStatusError::Io)
            })?
            .map_err(file_status_error)?;
        file_status(status)
    }

    /// Get static backing data for a file, if available and supported.
    pub fn get_static_file_backing_data(&self, fd: &FileFd<Platform>) -> Option<&'static [u8]> {
        let _ = self.broker_file(fd)?;
        None
    }
}

/// Per-call resolution context. The user may hold and mutate this as they wish.
#[derive(Clone, Debug)]
pub struct Context {
    cwd: Arc<ResolvedPath>,
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            cwd: Arc::new(ResolvedPath { components: vec![] }),
            user_info: UserInfo {
                user: 1000,
                group: 1000,
            },
        }
    }

    /// Resolve `path` against the current context.
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
                _ => components.push(component.into()),
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

/// Absolute normalized path, created from [`Context::resolve`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedPath {
    components: Vec<String>,
}

impl core::fmt::Display for ResolvedPath {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for component in &self.components {
            write!(formatter, "/{component}")?;
        }
        if self.components.is_empty() {
            formatter.write_str("/")?;
        }
        Ok(())
    }
}

struct BrokerFile {
    broker: Arc<dyn crate::broker::BrokerControl>,
    handle: ObjectHandle,
}

impl Drop for BrokerFile {
    fn drop(&mut self) {
        let _ = self.broker.close_object(self.handle);
    }
}

fn file_open_options(flags: OFlags) -> Result<(FileAccessMode, FileOpenFlags), OpenError> {
    const SUPPORTED_FLAGS: OFlags = OFlags::CREAT
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

    if flags.intersects(SUPPORTED_FLAGS.complement()) {
        unimplemented!("{flags:?}")
    }
    let access = match flags.bits() & 3 {
        0 => FileAccessMode::ReadOnly,
        1 => FileAccessMode::WriteOnly,
        2 => FileAccessMode::ReadWrite,
        _ => return Err(OpenError::AccessNotAllowed),
    };
    let mut output = FileOpenFlags::NONE;
    for (guest, broker) in [
        (OFlags::CREAT, FileOpenFlags::CREATE),
        (OFlags::TRUNC, FileOpenFlags::TRUNCATE),
        (OFlags::NOCTTY, FileOpenFlags::NO_CONTROLLING_TERMINAL),
        (OFlags::EXCL, FileOpenFlags::EXCLUSIVE),
        (OFlags::DIRECTORY, FileOpenFlags::DIRECTORY),
        (OFlags::NONBLOCK, FileOpenFlags::NONBLOCKING),
        (OFlags::LARGEFILE, FileOpenFlags::LARGE_FILE),
        (OFlags::NOFOLLOW, FileOpenFlags::NO_FOLLOW),
        (OFlags::APPEND, FileOpenFlags::APPEND),
        (OFlags::PATH, FileOpenFlags::PATH),
    ] {
        if flags.contains(guest) {
            output = output.union(broker);
        }
    }
    Ok((access, output))
}

fn file_mode(mode: Mode) -> FileMode {
    let bits = u16::try_from(mode.bits() & u32::from(FileMode::SUPPORTED.bits()))
        .expect("supported file mode bits fit in u16");
    FileMode::from_bits(bits).expect("masked file mode bits are supported")
}

const fn file_user(user: UserInfo) -> FileUser {
    FileUser {
        user: user.user,
        group: user.group,
    }
}

const fn file_seek_whence(whence: SeekWhence) -> FileSeekWhence {
    match whence {
        SeekWhence::RelativeToBeginning => FileSeekWhence::Beginning,
        SeekWhence::RelativeToCurrentOffset => FileSeekWhence::Current,
        SeekWhence::RelativeToEnd => FileSeekWhence::End,
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

fn path_error(error: FileError) -> Option<PathError> {
    match error {
        FileError::NoSuchFileOrDirectory => Some(PathError::NoSuchFileOrDirectory),
        FileError::NoSearchPermissions => Some(PathError::NoSearchPerms {
            #[cfg(debug_assertions)]
            dir: String::new(),
            #[cfg(debug_assertions)]
            perms: Mode::empty(),
        }),
        FileError::InvalidPathname => Some(PathError::InvalidPathname),
        FileError::MissingComponent => Some(PathError::MissingComponent),
        FileError::ComponentNotDirectory => Some(PathError::ComponentNotADirectory),
        _ => None,
    }
}

fn open_error(error: FileError) -> OpenError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::AccessNotAllowed => OpenError::AccessNotAllowed,
        FileError::NoWritePermissions => OpenError::NoWritePerms,
        FileError::ReadOnlyFs => OpenError::ReadOnlyFileSystem,
        FileError::AlreadyExists => OpenError::AlreadyExists,
        FileError::IsDirectory => OpenError::TruncateError(TruncateError::IsDirectory),
        FileError::NotForWriting => OpenError::TruncateError(TruncateError::NotForWriting),
        FileError::IsTerminalDevice => OpenError::TruncateError(TruncateError::IsTerminalDevice),
        _ => OpenError::Io,
    }
}

fn read_error(error: FileError) -> ReadError {
    match error {
        FileError::NotFile => ReadError::NotAFile,
        FileError::NotForReading => ReadError::NotForReading,
        _ => ReadError::Io,
    }
}

fn write_error(error: FileError) -> WriteError {
    match error {
        FileError::NotFile => WriteError::NotAFile,
        FileError::NotForWriting => WriteError::NotForWriting,
        _ => WriteError::Io,
    }
}

fn seek_error(error: FileError) -> SeekError {
    match error {
        FileError::NotFile => SeekError::NotAFile,
        FileError::InvalidOffset => SeekError::InvalidOffset,
        FileError::NonSeekable => SeekError::NonSeekable,
        _ => SeekError::Io,
    }
}

fn truncate_error(error: FileError) -> TruncateError {
    match error {
        FileError::IsDirectory => TruncateError::IsDirectory,
        FileError::NotForWriting => TruncateError::NotForWriting,
        FileError::IsTerminalDevice => TruncateError::IsTerminalDevice,
        _ => TruncateError::Io,
    }
}

fn chmod_error(error: FileError) -> ChmodError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NotOwner => ChmodError::NotTheOwner,
        FileError::ReadOnlyFs => ChmodError::ReadOnlyFileSystem,
        _ => ChmodError::Io,
    }
}

fn chown_error(error: FileError) -> ChownError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NotOwner => ChownError::NotTheOwner,
        FileError::ReadOnlyFs => ChownError::ReadOnlyFileSystem,
        _ => ChownError::Io,
    }
}

fn unlink_error(error: FileError) -> UnlinkError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => UnlinkError::NoWritePerms,
        FileError::IsDirectory => UnlinkError::IsADirectory,
        FileError::ReadOnlyFs => UnlinkError::ReadOnlyFileSystem,
        _ => UnlinkError::Io,
    }
}

fn mkdir_error(error: FileError) -> MkdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => MkdirError::NoWritePerms,
        FileError::AlreadyExists => MkdirError::AlreadyExists,
        FileError::ReadOnlyFs => MkdirError::ReadOnlyFileSystem,
        _ => MkdirError::Io,
    }
}

fn rmdir_error(error: FileError) -> RmdirError {
    if let Some(error) = path_error(error) {
        return error.into();
    }
    match error {
        FileError::NoWritePermissions => RmdirError::NoWritePerms,
        FileError::Busy => RmdirError::Busy,
        FileError::NotEmpty => RmdirError::NotEmpty,
        FileError::NotDirectory => RmdirError::NotADirectory,
        FileError::ReadOnlyFs => RmdirError::ReadOnlyFileSystem,
        _ => RmdirError::Io,
    }
}

fn read_dir_error(error: FileError) -> ReadDirError {
    match error {
        FileError::NotDirectory => ReadDirError::NotADirectory,
        _ => ReadDirError::Io,
    }
}

fn file_status_error(error: FileError) -> FileStatusError {
    path_error(error).map_or(FileStatusError::Io, Into::into)
}

fn file_status(status: BrokerFileStatus) -> Result<FileStatus, FileStatusError> {
    Ok(FileStatus {
        file_type: status.file_type,
        mode: Mode::from_bits_retain(u32::from(status.mode.bits())),
        size: usize::try_from(status.size).map_err(|_| FileStatusError::Io)?,
        owner: UserInfo {
            user: status.owner.user,
            group: status.owner.group,
        },
        node_info: status_node_info(status.node_info)?,
        blksize: usize::try_from(status.block_size).map_err(|_| FileStatusError::Io)?,
    })
}

fn directory_entries(entries: Vec<FileDirectoryEntry>) -> Result<Vec<DirEntry>, ReadDirError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(entries.len())
        .map_err(|_| ReadDirError::Io)?;
    for entry in entries {
        output.push(DirEntry {
            name: entry.name,
            file_type: entry.file_type,
            ino_info: entry.node_info.map(directory_node_info).transpose()?,
        });
    }
    Ok(output)
}

fn status_node_info(node: FileNodeInfo) -> Result<NodeInfo, FileStatusError> {
    Ok(NodeInfo {
        dev: usize::try_from(node.dev).map_err(|_| FileStatusError::Io)?,
        ino: usize::try_from(node.ino).map_err(|_| FileStatusError::Io)?,
        rdev: optional_device(node.rdev).map_err(|()| FileStatusError::Io)?,
    })
}

fn directory_node_info(node: FileNodeInfo) -> Result<NodeInfo, ReadDirError> {
    Ok(NodeInfo {
        dev: usize::try_from(node.dev).map_err(|_| ReadDirError::Io)?,
        ino: usize::try_from(node.ino).map_err(|_| ReadDirError::Io)?,
        rdev: optional_device(node.rdev).map_err(|()| ReadDirError::Io)?,
    })
}

fn optional_device(device: Option<u64>) -> Result<Option<core::num::NonZeroUsize>, ()> {
    device
        .map(|device| {
            usize::try_from(device)
                .ok()
                .and_then(core::num::NonZeroUsize::new)
                .ok_or(())
        })
        .transpose()
}

crate::fd::enable_fds_for_subsystem! {
    @ Platform: { sync::RawSyncPrimitivesProvider };
    File<Platform>;
    Arc<BrokerFile>;
    -> FileFd<Platform>;
}
