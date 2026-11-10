// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contents of regular files that runners map with `MAP_SHARED`.
//!
//! [`SharedMappings`] wraps the backend of a whole filesystem. The first shared mapping of a file
//! moves its contents, whatever backend holds them, into host memory that the broker lends to
//! every runner mapping the file. From then on reads, writes, truncation, and status of the file
//! go through that memory instead of the backend, so `read`, `write`, and every mapping of the
//! file see the same bytes.
//!
//! The memory lives while an open file that mapped it lives; the broker keeps each such open file
//! referenced by every process it lent the memory to until that process exits, as it cannot see
//! when a runner unmaps it. Once nothing holds the memory, it is written back to the backend and
//! forgotten. The memory keeps the file open, so its identity cannot be reused while the memory
//! exists.
//!
//! XXX(jayb): Memory could be released sooner, on a runner's report that its last mapping of it
//! is gone, rather than at process exit. It is also not written back on `fsync`/`msync`, nor when
//! the broker exits.

use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_platform::buffer::{Fault, ReadBuffer, WriteBuffer};
use thiserror::Error;

use super::backend::{
    Backend, BackendHandles, CreationMetadata, DirHandle, FileHandle, FileTerminal, HandleRef,
    PermissionInfo, Resolution, ResolvedDir, ResolvedFile, ResolvedTarget, SeekBehavior,
};
use super::errors::{
    ChmodError, ChownError, FileStatusError, MapSharedError, MkdirError, OpenError, ReadDirError,
    ReadError, RenameError, ResolutionError, RmdirError, SymlinkError, TruncateError, UnlinkError,
    WalkError, WriteError,
};
use super::{DirEntry, FileStatus, FileType, Mode, NodeInfo, OFlags};
use crate::BrokerError;
use crate::readiness::ReadinessSource;

/// Error accessing [`SharedFileMemory`].
#[derive(Debug, Error)]
pub enum SharedFileMemoryError {
    /// The host failed the access, as it may for any file I/O.
    #[error("I/O error")]
    Io,
    /// The access failed for a reason that is not the file's, such as a fault copying a buffer.
    #[error(transparent)]
    Broker(#[from] BrokerError),
}

impl From<Fault> for SharedFileMemoryError {
    fn from(fault: Fault) -> Self {
        Self::Broker(fault.into())
    }
}

/// Host memory holding the contents of one regular file, which runners map shared.
///
/// The memory's length is the file's length. Runners hold it writable, so they can change its
/// bytes and length at any time; implementations must stay memory-safe when they do, for example
/// by copying through `pread`/`pwrite` rather than mapping the memory in the broker.
pub trait SharedFileMemory: Send + Sync {
    /// Returns the file's length.
    fn length(&self) -> Result<u64, SharedFileMemoryError>;

    /// Truncates or zero-extends the file to `length` bytes.
    fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError>;

    /// Reads into `output` from `offset`, returning the bytes read, 0 at or past the end.
    fn read_at(
        &self,
        offset: usize,
        output: &mut dyn ReadBuffer,
    ) -> Result<usize, SharedFileMemoryError>;

    /// Writes `input` at `offset`, zero-filling any gap past the end, and returns the bytes
    /// written.
    fn write_at(
        &self,
        offset: usize,
        input: &dyn WriteBuffer,
    ) -> Result<usize, SharedFileMemoryError>;

    /// Returns the memory so the host that created it can recover its concrete type to lend it.
    fn as_any(&self) -> &dyn Any;
}

/// The memory a file's shared mappings map, and its name.
#[derive(Clone)]
pub struct SharedMapping {
    /// The file's contents.
    pub memory: Arc<dyn SharedFileMemory>,
    /// Name of the memory, which every process mapping the file keys futexes in it by.
    pub memory_id: SharedMemoryId,
}

/// Identifies a file across its open handles.
type FileIdentity = (u64, u64);

fn identity(node: NodeInfo) -> FileIdentity {
    (node.dev, node.ino)
}

/// The files whose contents are in shared memory, by identity. Open files that mapped the memory
/// hold it; this only finds it while they do.
type SharedFiles = spin::RwLock<HashMap<FileIdentity, Weak<SharedFile>>>;

/// A regular file whose contents are in shared memory, which writes the memory back to the
/// backend once nothing holds it anymore.
struct SharedFile {
    mapping: SharedMapping,
    identity: FileIdentity,
    backend: Arc<dyn Backend>,
    files: Arc<SharedFiles>,
    /// Keeps the file open, so that its identity is not reused while the memory exists.
    _file: FileHandle,
    /// A handle that may write the file, through which to write the memory back. Only such
    /// handles change the memory, so the memory needs no writing back without one.
    writer: spin::Mutex<Option<FileHandle>>,
}

impl SharedFile {
    fn memory(&self) -> &dyn SharedFileMemory {
        self.mapping.memory.as_ref()
    }

    /// Records that `handle`, which may write the file, is about to change the memory.
    fn note_writer(&self, handle: &FileHandle) {
        let mut writer = self.writer.lock();
        if writer.is_none() {
            *writer = Some(handle.clone());
        }
    }

    /// Copies the memory to the backend through `writer`.
    fn write_back(&self, writer: &FileHandle) -> Result<(), ()> {
        let mut chunk = alloc::vec![0; 64 * 1024];
        let mut offset = 0;
        loop {
            let read = self
                .memory()
                .read_at(offset, &mut chunk.as_mut_slice())
                .map_err(|_| ())?;
            if read == 0 {
                break;
            }
            let mut written = 0;
            while written < read {
                written += self
                    .backend
                    .write(writer, &&chunk[written..read], offset + written)
                    .map_err(|_| ())?;
            }
            offset += read;
        }
        self.backend.truncate(writer, offset).map_err(|_| ())
    }
}

impl Drop for SharedFile {
    fn drop(&mut self) {
        let Some(writer) = self.writer.get_mut().take() else {
            return;
        };
        // Holding the table keeps anyone from reading the file from the backend, or moving it
        // into new memory, before the backend has these contents.
        // XXX(jayb): Holds the table's spin lock across writing back, which stalls other users of
        // shared files meanwhile.
        let mut files = self.files.write();
        if self.write_back(&writer).is_err() {
            litebox_util_log::warn!(
                "failed to write back the shared memory of a file; its changes are lost"
            );
        }
        if files
            .get(&self.identity)
            .is_some_and(|file| file.strong_count() == 0)
        {
            files.remove(&self.identity);
        }
    }
}

/// A [`Backend`] whose regular files' contents [`Backend::map_shared`] moves into shared memory.
///
/// It wraps the backend of a whole filesystem, so that every mount shares one table of files.
pub struct SharedMappings<B: Backend> {
    inner: Arc<B>,
    files: Arc<SharedFiles>,
}

impl<B: Backend> SharedMappings<B> {
    /// Wrap `inner`, which serves every file of the filesystem.
    #[must_use]
    pub fn new(inner: B) -> Self {
        Self {
            inner: Arc::new(inner),
            files: Arc::default(),
        }
    }

    /// Returns the shared file that `status` describes, if its contents are in shared memory.
    fn shared_file(&self, status: &FileStatus) -> Option<Arc<SharedFile>> {
        if status.file_type != FileType::RegularFile {
            return None;
        }
        let files = self.files.read();
        if files.is_empty() {
            return None;
        }
        files
            .get(&identity(status.node_info))
            .and_then(Weak::upgrade)
    }

    /// Returns the shared file holding the contents of the file `h` opens, if any.
    fn shared_file_of(&self, h: &FileHandle) -> Result<Option<Arc<SharedFile>>, FileStatusError> {
        if self.files.read().is_empty() {
            return Ok(None);
        }
        // XXX(jayb): Every read and write looks up the file's identity while any file is mapped
        // shared; the handle could remember it instead.
        let status = self.inner.status(HandleRef::File(h))?;
        Ok(self.shared_file(&status))
    }

    /// Reports the length of the file `status` describes as its shared memory's, if it has any.
    fn patch_status(&self, mut status: FileStatus) -> Result<FileStatus, FileStatusError> {
        if let Some(shared) = self.shared_file(&status) {
            status.size = shared.memory().length().map_err(|_| FileStatusError::Io)?;
        }
        Ok(status)
    }
}

/// An open file of a [`SharedMappings`] backend.
#[derive(Clone)]
struct SharedMappingsFile {
    inner: FileHandle,
    /// The file's shared memory, once a shared mapping through this open file lent it, which
    /// stays alive while this does.
    held: Arc<spin::Once<Arc<SharedFile>>>,
}

/// The handle types of [`SharedMappings`], which only wraps open files.
struct Handles;

impl BackendHandles for Handles {
    type ResolvedDir<'a> = ();
    type ResolvedFile<'a> = ();
    type FileHandle = SharedMappingsFile;
    type DirHandle = ();
}

fn inner(h: &FileHandle) -> &FileHandle {
    &h.get_typed::<Handles>().inner
}

fn wrap(inner: FileHandle) -> FileHandle {
    FileHandle::from_typed::<Handles>(SharedMappingsFile {
        inner,
        held: Arc::default(),
    })
}

impl<B: Backend> Backend for SharedMappings<B> {
    fn root(&self) -> Result<ResolvedDir<'_>, WalkError> {
        self.inner.root()
    }

    fn resolve<'a>(
        &'a self,
        from: ResolvedDir<'a>,
        components: &[&str],
        authorize_dir_lookup: &dyn Fn(&PermissionInfo) -> Result<(), WalkError>,
    ) -> Result<Resolution<'a>, ResolutionError> {
        self.inner.resolve(from, components, authorize_dir_lookup)
    }

    fn read_link_at(&self, dir: &ResolvedDir<'_>, name: &str) -> Result<String, WalkError> {
        self.inner.read_link_at(dir, name)
    }

    fn open_dir(&self, dir: ResolvedDir<'_>, flags: OFlags) -> Result<DirHandle, OpenError> {
        self.inner.open_dir(dir, flags)
    }

    fn walking_dir_at<'a>(&'a self, dir: &DirHandle) -> Option<ResolvedDir<'a>> {
        self.inner.walking_dir_at(dir)
    }

    fn open_file(&self, file: ResolvedFile<'_>, flags: OFlags) -> Result<FileHandle, OpenError> {
        let handle = self.inner.open_file(file, flags)?;
        if flags.contains(OFlags::TRUNC)
            && !flags.contains(OFlags::PATH)
            && let Some(shared) = self.shared_file_of(&handle).map_err(|_| OpenError::Io)?
        {
            // The backend truncated its copy, which the shared memory supersedes.
            shared.memory().set_len(0).map_err(|_| OpenError::Io)?;
        }
        Ok(wrap(handle))
    }

    fn list_dir_at(&self, handle: DirHandle) -> Result<Vec<DirEntry>, ReadDirError> {
        self.inner.list_dir_at(handle)
    }

    fn lookup_at(&self, dir: &DirHandle, name: &str) -> Result<Option<DirEntry>, ReadDirError> {
        self.inner.lookup_at(dir, name)
    }

    fn read(
        &self,
        h: &FileHandle,
        buf: &mut dyn ReadBuffer,
        offset: usize,
    ) -> Result<usize, ReadError> {
        let h = inner(h);
        match self.shared_file_of(h).map_err(|_| ReadError::Io)? {
            Some(shared) => shared
                .memory()
                .read_at(offset, buf)
                .map_err(|error| match error {
                    SharedFileMemoryError::Io => ReadError::Io,
                    SharedFileMemoryError::Broker(error) => ReadError::Broker(error),
                }),
            None => self.inner.read(h, buf, offset),
        }
    }

    fn get_static_backing_data(&self, h: &FileHandle) -> Option<&'static [u8]> {
        // Static contents cannot change, so they are never moved into shared memory.
        self.inner.get_static_backing_data(inner(h))
    }

    fn write(
        &self,
        h: &FileHandle,
        buf: &dyn WriteBuffer,
        offset: usize,
    ) -> Result<usize, WriteError> {
        let h = inner(h);
        match self.shared_file_of(h).map_err(|_| WriteError::Io)? {
            Some(shared) => {
                shared.note_writer(h);
                shared
                    .memory()
                    .write_at(offset, buf)
                    .map_err(|error| match error {
                        SharedFileMemoryError::Io => WriteError::Io,
                        SharedFileMemoryError::Broker(error) => WriteError::Broker(error),
                    })
            }
            None => self.inner.write(h, buf, offset),
        }
    }

    fn truncate(&self, h: &FileHandle, length: usize) -> Result<(), TruncateError> {
        let h = inner(h);
        match self.shared_file_of(h).map_err(|_| TruncateError::Io)? {
            Some(shared) => {
                shared.note_writer(h);
                shared
                    .memory()
                    .set_len(length)
                    .map_err(|_| TruncateError::Io)
            }
            None => self.inner.truncate(h, length),
        }
    }

    fn seek_behavior(&self, h: &FileHandle) -> SeekBehavior {
        self.inner.seek_behavior(inner(h))
    }

    fn is_read_only(&self, h: &FileHandle) -> bool {
        self.inner.is_read_only(inner(h))
    }

    fn map_shared(
        &self,
        h: &FileHandle,
        writable: bool,
        create: &dyn Fn() -> Result<SharedMapping, BrokerError>,
    ) -> Result<SharedMapping, MapSharedError> {
        let file = h.get_typed::<Handles>();
        let status = self.inner.status(HandleRef::File(&file.inner))?;
        if status.file_type != FileType::RegularFile {
            return Err(MapSharedError::NotSupported);
        }
        // A file that cannot change needs no sharing: a private copy of it is exact, and does not
        // pin a copy of the whole file in the broker.
        if self.inner.is_read_only(&file.inner) {
            return Err(MapSharedError::NotSupported);
        }
        let shared = if let Some(shared) = self.shared_file(&status) {
            shared
        } else {
            let mapping = create()?;
            let mut chunk = alloc::vec![0; 64 * 1024];
            let mut offset = 0;
            loop {
                let read = self
                    .inner
                    .read(&file.inner, &mut chunk.as_mut_slice(), offset)
                    .map_err(|_| MapSharedError::Io)?;
                if read == 0 {
                    break;
                }
                let mut written = 0;
                while written < read {
                    written += mapping
                        .memory
                        .write_at(offset + written, &&chunk[written..read])?;
                }
                offset += read;
            }
            let new = Arc::new(SharedFile {
                mapping,
                identity: identity(status.node_info),
                backend: Arc::clone(&self.inner) as Arc<dyn Backend>,
                files: Arc::clone(&self.files),
                _file: file.inner.clone(),
                writer: spin::Mutex::new(None),
            });
            // XXX(jayb): A write through another handle between the copy above and recording the
            // memory below is lost.
            let mut files = self.files.write();
            if let Some(existing) = files.get(&new.identity).and_then(Weak::upgrade) {
                // Another mapping recorded memory first; this one, which nothing wrote, is
                // dropped once the table is no longer held.
                drop(files);
                existing
            } else {
                files.retain(|_, file| file.strong_count() > 0);
                files.insert(new.identity, Arc::downgrade(&new));
                drop(files);
                new
            }
        };
        if writable {
            shared.note_writer(&file.inner);
        }
        let held = file.held.call_once(|| Arc::clone(&shared));
        // An open file refers to one file throughout, so it holds that file's memory.
        debug_assert!(Arc::ptr_eq(held, &shared));
        Ok(shared.mapping.clone())
    }

    fn status(&self, h: HandleRef<'_>) -> Result<FileStatus, FileStatusError> {
        match h {
            HandleRef::File(h) => self.patch_status(self.inner.status(HandleRef::File(inner(h)))?),
            HandleRef::Dir(_) => self.inner.status(h),
        }
    }

    fn resolved_status(&self, target: &ResolvedTarget<'_>) -> Result<FileStatus, FileStatusError> {
        self.patch_status(self.inner.resolved_status(target)?)
    }

    fn terminal(&self, h: &FileHandle) -> Option<FileTerminal> {
        self.inner.terminal(inner(h))
    }

    fn readiness_source(&self, h: &FileHandle) -> Option<Arc<dyn ReadinessSource>> {
        self.inner.readiness_source(inner(h))
    }

    fn create_file_at(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<FileHandle, OpenError> {
        Ok(wrap(self.inner.create_file_at(parent, name, metadata)?))
    }

    fn symlink_at(
        &self,
        dir: ResolvedDir<'_>,
        name: &str,
        target: &str,
        metadata: CreationMetadata,
    ) -> Result<(), SymlinkError> {
        self.inner.symlink_at(dir, name, target, metadata)
    }

    fn mkdir_at(
        &self,
        parent: ResolvedDir<'_>,
        name: &str,
        metadata: CreationMetadata,
    ) -> Result<DirHandle, MkdirError> {
        self.inner.mkdir_at(parent, name, metadata)
    }

    fn unlink_at(&self, parent: ResolvedDir<'_>, name: &str) -> Result<(), UnlinkError> {
        self.inner.unlink_at(parent, name)
    }

    fn rmdir_at(&self, parent: ResolvedDir<'_>, name: &str) -> Result<(), RmdirError> {
        self.inner.rmdir_at(parent, name)
    }

    fn rename_at(
        &self,
        old_dir: DirHandle,
        old_name: &str,
        new_dir: DirHandle,
        new_name: &str,
    ) -> Result<(), RenameError> {
        self.inner.rename_at(old_dir, old_name, new_dir, new_name)
    }

    fn chmod(&self, h: ResolvedTarget<'_>, mode: Mode) -> Result<(), ChmodError> {
        self.inner.chmod(h, mode)
    }

    fn chown(
        &self,
        h: ResolvedTarget<'_>,
        user: Option<u16>,
        group: Option<u16>,
    ) -> Result<(), ChownError> {
        self.inner.chown(h, user, group)
    }
}
