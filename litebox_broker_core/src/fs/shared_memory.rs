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
}

/// Host memory that holds one file's contents.
///
/// Its size is the file's size: a runner accessing a mapping past it faults, as Linux raises
/// `SIGBUS` past the end of a mapped file.
pub trait SharedFileMemory: Send + Sync + Any {
    /// Copies bytes from `offset` into `buffer`, returning how many were copied, which is fewer
    /// than requested only at the end of the memory.
    fn read_at(&self, offset: usize, buffer: &mut [u8]) -> Result<usize, SharedFileMemoryError>;

    /// Copies `data` to `offset`. The memory must already be large enough.
    fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), SharedFileMemoryError>;

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

/// The shared memory holding a file's contents, as returned to a runner that maps the file.
#[derive(Clone)]
pub struct SharedFileMapping {
    /// Identity of the file, the same for every process that maps it.
    pub identity: u128,
    /// The memory holding the file's contents.
    pub memory: Arc<dyn SharedFileMemory>,
}

impl core::fmt::Debug for SharedFileMapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedFileMapping")
            .field("identity", &self.identity)
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
    use spin::mutex::SpinMutex as Mutex;

    #[derive(Default)]
    pub(crate) struct VecMemory(pub(crate) Mutex<Vec<u8>>);

    impl SharedFileMemory for VecMemory {
        fn read_at(
            &self,
            offset: usize,
            buffer: &mut [u8],
        ) -> Result<usize, SharedFileMemoryError> {
            let data = self.0.lock();
            let start = offset.min(data.len());
            let end = offset.saturating_add(buffer.len()).min(data.len());
            buffer[..end - start].copy_from_slice(&data[start..end]);
            Ok(end - start)
        }

        fn write_at(&self, offset: usize, data: &[u8]) -> Result<(), SharedFileMemoryError> {
            let mut memory = self.0.lock();
            let end = offset + data.len();
            if end > memory.len() {
                return Err(SharedFileMemoryError::Io);
            }
            memory[offset..end].copy_from_slice(data);
            Ok(())
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            self.0.lock().resize(length, 0);
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    pub(crate) struct VecMemoryProvider;

    impl SharedFileMemoryProvider for VecMemoryProvider {
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            Ok(Arc::new(VecMemory(Mutex::new(contents.to_vec()))))
        }
    }
}
