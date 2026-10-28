// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host shared memory holding file contents, so that runners can map files `MAP_SHARED`.
//!
//! A backend whose files live in memory can move a file's contents into a [`SharedFileMemory`]
//! the first time a runner maps it. From then on, reads, writes, and truncation go to that
//! memory, and every runner that maps the file maps the same host pages, so mappings and file
//! I/O stay coherent without copying anything back.
//!
//! The broker core never maps this memory itself. The deployment creates it (for example, as a
//! memfd) through a [`SharedFileMemoryProvider`] and delivers it to runners out of band.

use alloc::sync::Arc;
use core::any::Any;

use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Once;
use thiserror::Error;

/// Error accessing or creating [`SharedFileMemory`].
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SharedFileMemoryError {
    /// The host could not provide enough memory.
    #[error("out of host shared memory")]
    NoMemory,
    /// The host failed to access the memory.
    #[error("host shared memory I/O failed")]
    Io,
    /// The host cannot shrink the memory while it is mapped, as Windows refuses to truncate a
    /// file with mapped views.
    #[error("host shared memory is mapped")]
    Busy,
    /// Copying to or from the caller's buffer faulted.
    #[error("buffer access faulted")]
    Fault,
}

impl From<litebox_platform::buffer::Fault> for SharedFileMemoryError {
    fn from(_: litebox_platform::buffer::Fault) -> Self {
        Self::Fault
    }
}

/// Host memory that holds one file's contents.
///
/// Its size is the file's size: a runner accessing a mapping past it faults, as Linux raises
/// `SIGBUS` past the end of a mapped file.
pub trait SharedFileMemory: Send + Sync + Any {
    /// Copies bytes from `offset` into `buffer`, returning how many were copied, which is fewer
    /// than `buffer.len()` only at the end of the memory.
    fn read_at(
        &self,
        offset: usize,
        buffer: &mut dyn ReadBuffer,
    ) -> Result<usize, SharedFileMemoryError>;

    /// Copies all of `data` to `offset`. The memory must already be large enough.
    fn write_at(&self, offset: usize, data: &dyn WriteBuffer) -> Result<(), SharedFileMemoryError>;

    /// Returns the size in bytes.
    ///
    /// A runner that may map the memory writable may also be able to grow it, so the broker
    /// asks the memory rather than remembering the size, as if the runner had extended the
    /// file, which it may write anyway.
    fn size(&self) -> Result<usize, SharedFileMemoryError>;

    /// Changes the size to `length` bytes, zero-filling any added bytes.
    fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError>;

    /// Returns `self` for the deployment to recover its concrete type, to deliver the memory.
    fn as_any(&self) -> &dyn Any;
}

/// Creates [`SharedFileMemory`] for a deployment.
pub trait SharedFileMemoryProvider: Send + Sync {
    /// Creates memory of `contents.len()` bytes that initially holds `contents`.
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError>;
}

/// A file's contents in host shared memory, which every runner mapping the file maps.
pub struct SharedFileContents {
    memory: Arc<dyn SharedFileMemory>,
    /// Names the memory for futexes, issued when a runner first maps the file.
    memory_id: Once<SharedMemoryId>,
}

impl SharedFileContents {
    /// Holds a file's contents in `memory`.
    pub fn new(memory: Arc<dyn SharedFileMemory>) -> Self {
        Self {
            memory,
            memory_id: Once::new(),
        }
    }

    /// Returns the memory holding the file's contents.
    pub fn memory(&self) -> &Arc<dyn SharedFileMemory> {
        &self.memory
    }

    /// Returns the ID naming the memory, issuing it with `issue` the first time.
    pub(crate) fn memory_id<E>(
        &self,
        issue: impl FnOnce() -> Result<SharedMemoryId, E>,
    ) -> Result<SharedMemoryId, E> {
        self.memory_id.try_call_once(issue).copied()
    }
}

/// The shared memory holding a file's contents, as returned to a runner that maps the file.
#[derive(Clone)]
pub struct SharedFileMapping {
    /// Names the memory, the same for every process that maps the file.
    pub memory_id: SharedMemoryId,
    /// The memory holding the file's contents.
    pub memory: Arc<dyn SharedFileMemory>,
    /// Whether the runner may map the memory writable.
    pub writable: bool,
}

impl core::fmt::Debug for SharedFileMapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedFileMapping")
            .field("memory_id", &self.memory_id)
            .field("writable", &self.writable)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod test_memory {
    //! A [`SharedFileMemory`] in an ordinary vector, for tests.

    use super::{SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::any::Any;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
    use spin::mutex::SpinMutex as Mutex;

    struct VecMemory {
        data: Mutex<Vec<u8>>,
        /// Whether shrinking fails, as on Windows while the memory is mapped.
        refuse_shrink: bool,
    }

    impl SharedFileMemory for VecMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut dyn ReadBuffer,
        ) -> Result<usize, SharedFileMemoryError> {
            let data = self.data.lock();
            let start = offset.min(data.len());
            let end = offset.saturating_add(buffer.len()).min(data.len());
            buffer.copy_from_slice_at(0, &data[start..end])?;
            Ok(end - start)
        }

        fn write_at(
            &self,
            offset: usize,
            data: &dyn WriteBuffer,
        ) -> Result<(), SharedFileMemoryError> {
            let mut memory = self.data.lock();
            let end = offset + data.len();
            if end > memory.len() {
                return Err(SharedFileMemoryError::Io);
            }
            data.copy_to_slice_at(0, &mut memory[offset..end])?;
            Ok(())
        }

        fn size(&self) -> Result<usize, SharedFileMemoryError> {
            Ok(self.data.lock().len())
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            let mut data = self.data.lock();
            if self.refuse_shrink && length < data.len() {
                return Err(SharedFileMemoryError::Busy);
            }
            data.resize(length, 0);
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Creates vector memory, which refuses to shrink if the field is set.
    pub(crate) struct VecMemoryProvider(pub(crate) bool);

    impl SharedFileMemoryProvider for VecMemoryProvider {
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            Ok(Arc::new(VecMemory {
                data: Mutex::new(contents.to_vec()),
                refuse_shrink: self.0,
            }))
        }
    }
}
