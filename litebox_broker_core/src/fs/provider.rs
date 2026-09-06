// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Adapter from the LiteBox filesystem engine to broker filesystem contracts.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::backend::{Backend, DeviceIo};
use super::composer::Composer;
use super::errors::{
    ChmodError, ChownError, FileStatusError, MkdirError, OpenError, PathError, ReadDirError,
    ReadError, RmdirError, SeekError, TruncateError, UnlinkError, WriteError,
};
use super::resolver::{Filesystem, FilesystemOpenFile};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags, SeekWhence, UserInfo};
use super::{FilesystemProvider, OpenFileDescription as BrokerOpenFileDescription};
use crate::AssociationCancellation;
use crate::random::RandomProvider;
use crate::stdio::StdioProvider;
use litebox_broker_protocol::fs::{
    FilesystemDirectoryEntry, FilesystemError, FilesystemFileStatus, FilesystemFileType,
    FilesystemNamespace, FilesystemNodeInfo, FilesystemSeekWhence, FilesystemUser,
    paginate_directory_entries,
};
use litebox_platform::sync::RawSyncPrimitivesProvider;

/// Routes each filesystem namespace to its isolated provider.
pub struct NamespacedFilesystemProvider {
    guest: Arc<dyn FilesystemProvider>,
    windows_registry: Arc<dyn FilesystemProvider>,
}

impl NamespacedFilesystemProvider {
    /// Creates a provider over isolated guest and Windows-registry filesystems.
    pub fn new(
        guest: Arc<dyn FilesystemProvider>,
        windows_registry: Arc<dyn FilesystemProvider>,
    ) -> Self {
        Self {
            guest,
            windows_registry,
        }
    }

    fn provider(&self, namespace: FilesystemNamespace) -> &dyn FilesystemProvider {
        match namespace {
            FilesystemNamespace::Guest => &*self.guest,
            FilesystemNamespace::WindowsRegistry => &*self.windows_registry,
        }
    }
}

impl FilesystemProvider for NamespacedFilesystemProvider {
    fn open(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        flags: u32,
        mode: u32,
    ) -> Result<Arc<dyn BrokerOpenFileDescription>, FilesystemError> {
        self.provider(namespace)
            .open(cancellation, namespace, path, user, flags, mode)
    }

    fn path_status(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<FilesystemFileStatus, FilesystemError> {
        self.provider(namespace)
            .path_status(cancellation, namespace, path, user)
    }

    fn chmod(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> Result<(), FilesystemError> {
        self.provider(namespace)
            .chmod(cancellation, namespace, path, user, mode)
    }

    fn chown(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        acting_user: FilesystemUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), FilesystemError> {
        self.provider(namespace)
            .chown(cancellation, namespace, path, acting_user, user, group)
    }

    fn unlink(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<(), FilesystemError> {
        self.provider(namespace)
            .unlink(cancellation, namespace, path, user)
    }

    fn mkdir(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> Result<(), FilesystemError> {
        self.provider(namespace)
            .mkdir(cancellation, namespace, path, user, mode)
    }

    fn rmdir(
        &self,
        cancellation: &AssociationCancellation,
        namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<(), FilesystemError> {
        self.provider(namespace)
            .rmdir(cancellation, namespace, path, user)
    }
}

/// Exposes a LiteBox filesystem engine as a broker filesystem provider.
pub struct FilesystemProviderAdapter<Platform, FsBackend>
where
    Platform: RawSyncPrimitivesProvider,
    FsBackend: Backend + 'static,
{
    fs: Arc<Filesystem<Platform, FsBackend>>,
    random: Arc<dyn RandomProvider>,
    stdio: Arc<dyn StdioProvider>,
}

impl<Platform, FsBackend> FilesystemProviderAdapter<Platform, FsBackend>
where
    Platform: RawSyncPrimitivesProvider,
    FsBackend: Backend + 'static,
{
    /// Creates a provider using the given filesystem and device-I/O providers.
    pub fn new(
        fs: Filesystem<Platform, FsBackend>,
        random: Arc<dyn RandomProvider>,
        stdio: Arc<dyn StdioProvider>,
    ) -> Self {
        Self {
            fs: Arc::new(fs),
            random,
            stdio,
        }
    }
}

/// Creates the isolated in-memory filesystem used by the Windows registry shim.
pub fn create_windows_registry_provider<Platform>(
    random: Arc<dyn RandomProvider>,
    stdio: Arc<dyn StdioProvider>,
) -> Result<Arc<dyn FilesystemProvider>, &'static str>
where
    Platform: RawSyncPrimitivesProvider + Send + Sync + 'static,
{
    let in_mem = super::in_mem::InMem::<Platform>::new_initialized([(
        "/",
        super::in_mem::InitialNode::Directory {
            mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
            owner: UserInfo::ROOT,
        },
    )]);
    let backend = Composer::builder()
        .mount_nestable("/", |allocators| {
            super::overlay::Overlay::<Platform>::new(
                in_mem,
                super::tar_ro::TarRo::new(super::tar_ro::EMPTY_TAR_FILE.into(), allocators.next()),
                allocators.next(),
            )
        })
        .build()
        .map_err(|_| "failed to construct broker registry filesystem")?;
    Ok(Arc::new(FilesystemProviderAdapter::new(
        Filesystem::<Platform, _>::new(backend),
        random,
        stdio,
    )))
}

impl<Platform, FsBackend> FilesystemProvider for FilesystemProviderAdapter<Platform, FsBackend>
where
    Platform: RawSyncPrimitivesProvider + Send + Sync + 'static,
    FsBackend: Backend + 'static,
{
    fn open(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        flags: u32,
        mode: u32,
    ) -> Result<Arc<dyn BrokerOpenFileDescription>, FilesystemError> {
        let file = self
            .fs
            .open(
                user_info(user),
                path,
                OFlags::from_bits_retain(flags),
                Mode::from_bits_retain(mode),
            )
            .map_err(fs_open_error)?;
        Ok(Arc::new(OpenFileDescriptionAdapter {
            fs: Arc::clone(&self.fs),
            file,
            random: Arc::clone(&self.random),
            stdio: Arc::clone(&self.stdio),
        }))
    }

    fn path_status(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<FilesystemFileStatus, FilesystemError> {
        self.fs
            .file_status(user_info(user), path)
            .map_err(fs_file_status_error)
            .map(file_status)
    }

    fn chmod(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> Result<(), FilesystemError> {
        self.fs
            .chmod(user_info(user), path, Mode::from_bits_retain(mode))
            .map_err(fs_chmod_error)
    }

    fn chown(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        acting_user: FilesystemUser,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), FilesystemError> {
        self.fs
            .chown(user_info(acting_user), path, user, group)
            .map_err(fs_chown_error)
    }

    fn unlink(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<(), FilesystemError> {
        self.fs
            .unlink(user_info(user), path)
            .map_err(fs_unlink_error)
    }

    fn mkdir(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
        mode: u32,
    ) -> Result<(), FilesystemError> {
        self.fs
            .mkdir(user_info(user), path, Mode::from_bits_retain(mode))
            .map_err(fs_mkdir_error)
    }

    fn rmdir(
        &self,
        _cancellation: &AssociationCancellation,
        _namespace: FilesystemNamespace,
        path: &str,
        user: FilesystemUser,
    ) -> Result<(), FilesystemError> {
        self.fs.rmdir(user_info(user), path).map_err(fs_rmdir_error)
    }
}

struct OpenFileDescriptionAdapter<Platform, FsBackend>
where
    Platform: RawSyncPrimitivesProvider,
    FsBackend: Backend + 'static,
{
    fs: Arc<Filesystem<Platform, FsBackend>>,
    file: FilesystemOpenFile<Platform>,
    random: Arc<dyn RandomProvider>,
    stdio: Arc<dyn StdioProvider>,
}

impl<Platform, FsBackend> BrokerOpenFileDescription
    for OpenFileDescriptionAdapter<Platform, FsBackend>
where
    Platform: RawSyncPrimitivesProvider + Send + Sync + 'static,
    FsBackend: Backend + 'static,
{
    fn read(
        &self,
        cancellation: &AssociationCancellation,
        output: &mut [u8],
        offset: Option<u64>,
    ) -> Result<usize, FilesystemError> {
        self.fs
            .read(
                &BrokerDeviceIo {
                    cancellation,
                    random: &*self.random,
                    stdio: &*self.stdio,
                },
                &self.file,
                output,
                offset
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| FilesystemError::InvalidOffset)?,
            )
            .map_err(fs_read_error)
    }

    fn write(
        &self,
        cancellation: &AssociationCancellation,
        input: &[u8],
        offset: Option<u64>,
    ) -> Result<usize, FilesystemError> {
        self.fs
            .write(
                &BrokerDeviceIo {
                    cancellation,
                    random: &*self.random,
                    stdio: &*self.stdio,
                },
                &self.file,
                input,
                offset
                    .map(usize::try_from)
                    .transpose()
                    .map_err(|_| FilesystemError::InvalidOffset)?,
            )
            .map_err(fs_write_error)
    }

    fn seek(
        &self,
        _cancellation: &AssociationCancellation,
        offset: i64,
        whence: FilesystemSeekWhence,
    ) -> Result<u64, FilesystemError> {
        let offset = isize::try_from(offset).map_err(|_| FilesystemError::InvalidOffset)?;
        let offset = self
            .fs
            .seek(&self.file, offset, seek_whence(whence))
            .map_err(fs_seek_error)?;
        u64::try_from(offset).map_err(|_| FilesystemError::InvalidOffset)
    }

    fn truncate(
        &self,
        _cancellation: &AssociationCancellation,
        length: u64,
        reset_offset: bool,
    ) -> Result<(), FilesystemError> {
        self.fs
            .truncate(
                &self.file,
                usize::try_from(length).map_err(|_| FilesystemError::InvalidOffset)?,
                reset_offset,
            )
            .map_err(fs_truncate_error)
    }

    fn read_directory(
        &self,
        _cancellation: &AssociationCancellation,
        start_index: u64,
        maximum_encoded_length: usize,
    ) -> Result<(Vec<FilesystemDirectoryEntry>, Option<u64>), FilesystemError> {
        let entries = self
            .fs
            .read_dir(&self.file)
            .map_err(fs_read_dir_error)?
            .into_iter()
            .map(directory_entry)
            .collect::<Vec<_>>();
        let start_index = usize::try_from(start_index)
            .map_err(|_| FilesystemError::InvalidOffset)?
            .min(entries.len());
        paginate_directory_entries(&entries, start_index, maximum_encoded_length)
            .map_err(|_| FilesystemError::Io)
    }

    fn status(
        &self,
        _cancellation: &AssociationCancellation,
    ) -> Result<FilesystemFileStatus, FilesystemError> {
        self.fs
            .handle_status(&self.file)
            .map_err(fs_file_status_error)
            .map(file_status)
    }
}

struct BrokerDeviceIo<'a> {
    cancellation: &'a AssociationCancellation,
    random: &'a dyn RandomProvider,
    stdio: &'a dyn StdioProvider,
}

impl DeviceIo for BrokerDeviceIo<'_> {
    fn read_stdin(&self, output: &mut [u8]) -> Result<usize, ReadError> {
        if output.is_empty() {
            return Ok(0);
        }
        self.stdio
            .read(self.cancellation, output)
            .map_err(|_| ReadError::Io)
    }

    fn write_stdio(
        &self,
        stream: litebox_broker_protocol::stdio::StdioOutputStream,
        input: &[u8],
    ) -> Result<usize, WriteError> {
        if input.is_empty() {
            return Ok(0);
        }
        self.stdio
            .write(self.cancellation, stream, input)
            .map_err(|_| WriteError::Io)
    }

    fn fill_random(&self, output: &mut [u8]) -> Result<(), ReadError> {
        if output.is_empty() {
            return Ok(());
        }
        self.random.fill(output).map_err(|_| ReadError::Io)
    }
}

const fn user_info(user: FilesystemUser) -> UserInfo {
    UserInfo {
        user: user.user,
        group: user.group,
    }
}

const fn seek_whence(whence: FilesystemSeekWhence) -> SeekWhence {
    match whence {
        FilesystemSeekWhence::Beginning => SeekWhence::RelativeToBeginning,
        FilesystemSeekWhence::Current => SeekWhence::RelativeToCurrentOffset,
        FilesystemSeekWhence::End => SeekWhence::RelativeToEnd,
    }
}

fn file_status(status: FileStatus) -> FilesystemFileStatus {
    FilesystemFileStatus {
        file_type: file_type(status.file_type),
        mode: status.mode.bits(),
        size: status.size as u64,
        owner: FilesystemUser {
            user: status.owner.user,
            group: status.owner.group,
        },
        node_info: node_info(status.node_info),
        block_size: status.blksize as u64,
    }
}

fn directory_entry(entry: DirEntry) -> FilesystemDirectoryEntry {
    FilesystemDirectoryEntry {
        name: entry.name,
        file_type: file_type(entry.file_type),
        node_info: entry.ino_info.map(node_info),
    }
}

const fn file_type(file_type: FileType) -> FilesystemFileType {
    match file_type {
        FileType::RegularFile => FilesystemFileType::RegularFile,
        FileType::Directory => FilesystemFileType::Directory,
        FileType::CharacterDevice => FilesystemFileType::CharacterDevice,
    }
}

fn node_info(node_info: NodeInfo) -> FilesystemNodeInfo {
    FilesystemNodeInfo {
        dev: node_info.dev as u64,
        ino: node_info.ino as u64,
        rdev: node_info.rdev.map(|rdev| rdev.get() as u64),
    }
}

fn fs_path_error(error: PathError) -> FilesystemError {
    match error {
        PathError::NoSuchFileOrDirectory => FilesystemError::NoSuchFileOrDirectory,
        PathError::NoSearchPerms { .. } => FilesystemError::NoSearchPermissions,
        PathError::InvalidPathname => FilesystemError::InvalidPathname,
        PathError::MissingComponent => FilesystemError::MissingComponent,
        PathError::ComponentNotADirectory => FilesystemError::ComponentNotDirectory,
    }
}

fn fs_open_error(error: OpenError) -> FilesystemError {
    match error {
        OpenError::AccessNotAllowed => FilesystemError::AccessNotAllowed,
        OpenError::NoWritePerms => FilesystemError::NoWritePermissions,
        OpenError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        OpenError::AlreadyExists => FilesystemError::AlreadyExists,
        OpenError::TruncateError(error) => fs_truncate_error(error),
        OpenError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_read_error(error: ReadError) -> FilesystemError {
    match error {
        ReadError::NotAFile => FilesystemError::NotFile,
        ReadError::NotForReading => FilesystemError::NotForReading,
        _ => FilesystemError::Io,
    }
}

fn fs_write_error(error: WriteError) -> FilesystemError {
    match error {
        WriteError::NotAFile => FilesystemError::NotFile,
        WriteError::NotForWriting => FilesystemError::NotForWriting,
        _ => FilesystemError::Io,
    }
}

fn fs_seek_error(error: SeekError) -> FilesystemError {
    match error {
        SeekError::NotAFile => FilesystemError::NotFile,
        SeekError::InvalidOffset => FilesystemError::InvalidOffset,
        SeekError::NonSeekable => FilesystemError::NonSeekable,
        _ => FilesystemError::Io,
    }
}

fn fs_truncate_error(error: TruncateError) -> FilesystemError {
    match error {
        TruncateError::IsDirectory => FilesystemError::IsDirectory,
        TruncateError::NotForWriting => FilesystemError::NotForWriting,
        TruncateError::IsTerminalDevice => FilesystemError::IsTerminalDevice,
        TruncateError::ClosedFd | TruncateError::Io => FilesystemError::Io,
    }
}

fn fs_chmod_error(error: ChmodError) -> FilesystemError {
    match error {
        ChmodError::NotTheOwner => FilesystemError::NotOwner,
        ChmodError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        ChmodError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_chown_error(error: ChownError) -> FilesystemError {
    match error {
        ChownError::NotTheOwner => FilesystemError::NotOwner,
        ChownError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        ChownError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_unlink_error(error: UnlinkError) -> FilesystemError {
    match error {
        UnlinkError::NoWritePerms => FilesystemError::NoWritePermissions,
        UnlinkError::IsADirectory => FilesystemError::IsDirectory,
        UnlinkError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        UnlinkError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_mkdir_error(error: MkdirError) -> FilesystemError {
    match error {
        MkdirError::NoWritePerms => FilesystemError::NoWritePermissions,
        MkdirError::AlreadyExists => FilesystemError::AlreadyExists,
        MkdirError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        MkdirError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_rmdir_error(error: RmdirError) -> FilesystemError {
    match error {
        RmdirError::NoWritePerms => FilesystemError::NoWritePermissions,
        RmdirError::Busy => FilesystemError::Busy,
        RmdirError::NotEmpty => FilesystemError::NotEmpty,
        RmdirError::NotADirectory => FilesystemError::NotDirectory,
        RmdirError::ReadOnlyFileSystem => FilesystemError::ReadOnlyFilesystem,
        RmdirError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}

fn fs_read_dir_error(error: ReadDirError) -> FilesystemError {
    match error {
        ReadDirError::NotADirectory => FilesystemError::NotDirectory,
        _ => FilesystemError::Io,
    }
}

fn fs_file_status_error(error: FileStatusError) -> FilesystemError {
    match error {
        FileStatusError::PathError(error) => fs_path_error(error),
        _ => FilesystemError::Io,
    }
}
