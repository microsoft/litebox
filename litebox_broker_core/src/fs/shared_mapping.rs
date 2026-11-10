// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Contents of regular files that runners map with `MAP_SHARED`.
//!
//! The first shared mapping of a file moves its contents, whatever backend holds them, into host
//! memory that the broker lends to every runner mapping the file. From then on the resolver reads,
//! writes, truncates, and sizes the file through that memory instead of the backend, so `read`,
//! `write`, and every mapping of the file see the same bytes.
//!
//! The memory lives while an open file that mapped it lives; the broker keeps each such open file
//! referenced by every process it lent the memory to until that process exits, as it cannot see
//! when a runner unmaps it. Once nothing holds the memory, the next shared mapping writes it back
//! to the backend and forgets it. The memory keeps the file open, so its identity cannot be
//! reused while the memory exists.
//!
//! XXX(jayb): Memory could be released sooner: on a runner's report that its last mapping of it is
//! gone, rather than at process exit, and as soon as nothing holds it, rather than at the next
//! shared mapping. It is also not written back on `fsync`/`msync`, nor when the broker exits.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_platform::buffer::{Fault, ReadBuffer, WriteBuffer};
use thiserror::Error;

use super::backend::FileHandle;
use super::{FileStatus, FileType, NodeInfo};
use crate::BrokerError;

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

/// A regular file whose contents are in shared memory.
pub(super) struct SharedFile {
    pub(super) mapping: SharedMapping,
    /// Keeps the file open, so that its identity is not reused while the memory exists.
    _file: FileHandle,
    /// A handle that may write the file, through which to write the memory back. Only such
    /// handles change the memory, so the memory needs no writing back without one.
    writer: spin::Mutex<Option<FileHandle>>,
}

impl SharedFile {
    pub(super) fn new(mapping: SharedMapping, file: FileHandle) -> Self {
        Self {
            mapping,
            _file: file,
            writer: spin::Mutex::new(None),
        }
    }

    pub(super) fn memory(&self) -> &dyn SharedFileMemory {
        self.mapping.memory.as_ref()
    }

    /// Records that `handle`, which may write the file, is about to change the memory.
    pub(super) fn note_writer(&self, handle: &FileHandle) {
        let mut writer = self.writer.lock();
        if writer.is_none() {
            *writer = Some(handle.clone());
        }
    }

    /// Returns the handle to write the memory back through, if it may have changed.
    pub(super) fn writer(&self) -> Option<FileHandle> {
        self.writer.lock().clone()
    }
}

/// Identifies a file across its open handles.
type FileIdentity = (u64, u64);

fn identity(node: NodeInfo) -> FileIdentity {
    (node.dev, node.ino)
}

/// The files whose contents are in shared memory, by identity.
#[derive(Default)]
pub(super) struct SharedMappings {
    files: spin::RwLock<HashMap<FileIdentity, Arc<SharedFile>>>,
}

impl SharedMappings {
    /// Returns whether no file is in shared memory, so callers can skip looking up identities.
    pub(super) fn is_empty(&self) -> bool {
        self.files.read().is_empty()
    }

    /// Returns the shared file that `status` describes, if its contents are in shared memory.
    pub(super) fn get(&self, status: &FileStatus) -> Option<Arc<SharedFile>> {
        if status.file_type != FileType::RegularFile || self.is_empty() {
            return None;
        }
        self.files.read().get(&identity(status.node_info)).cloned()
    }

    /// Records `file` for the file with `node` identity, unless another caller did first, and
    /// returns the one recorded.
    pub(super) fn insert(&self, node: NodeInfo, file: Arc<SharedFile>) -> Arc<SharedFile> {
        Arc::clone(self.files.write().entry(identity(node)).or_insert(file))
    }

    /// Writes back with `write_back`, and forgets, every shared file that nothing but this table
    /// holds.
    ///
    /// XXX(jayb): Holds the table's spin lock across writing back, which stalls other users of
    /// shared files meanwhile, so that none reads the backend before it is written back.
    pub(super) fn release_unheld(&self, mut write_back: impl FnMut(&SharedFile)) {
        let mut files = self.files.write();
        let unheld: Vec<FileIdentity> = files
            .iter()
            .filter(|(_, file)| Arc::strong_count(file) == 1)
            .map(|(identity, _)| *identity)
            .collect();
        for identity in unheld {
            if let Some(file) = files.remove(&identity) {
                write_back(&file);
            }
        }
    }

    /// Reports the length of the file `status` describes as its shared memory's, if it has any.
    pub(super) fn patch_status(
        &self,
        status: &mut FileStatus,
    ) -> Result<(), SharedFileMemoryError> {
        if let Some(file) = self.get(status) {
            status.size = file.memory().length()?;
        }
        Ok(())
    }
}
