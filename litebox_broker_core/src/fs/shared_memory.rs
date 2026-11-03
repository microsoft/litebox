// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded host storage for file contents.
//!
//! A backend moves a file's contents into [`SharedFileMemory`] the first time
//! [`Backend::map_shared`](super::backend::Backend::map_shared) is called. Subsequent reads,
//! writes, truncations, and requests for the object use the same storage.
//!
//! [`SharedFileLimit`] bounds how many files hold host resources at once.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use thiserror::Error;

use super::errors::{MapSharedError, ReadError, TruncateError, WriteError};

/// Error accessing, creating, or exporting a host object holding a file's contents.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SharedFileMemoryError {
    /// The host could not provide enough memory.
    #[error("out of host shared memory")]
    NoMemory,
    /// The host failed to access the memory.
    #[error("host shared memory I/O failed")]
    Io,
    /// The host cannot shrink the memory while it is mapped.
    #[error("host shared memory is mapped")]
    Busy,
    /// Copying to or from the caller's buffer faulted.
    #[error("buffer access faulted")]
    Fault,
    /// The host cannot provide a handle with the requested rights.
    #[error("host cannot provide a handle to the object")]
    Unsupported,
}

impl From<litebox_platform::buffer::Fault> for SharedFileMemoryError {
    fn from(_: litebox_platform::buffer::Fault) -> Self {
        Self::Fault
    }
}

impl From<SharedFileMemoryError> for ReadError {
    fn from(error: SharedFileMemoryError) -> Self {
        match error {
            SharedFileMemoryError::Fault => litebox_platform::buffer::Fault.into(),
            _ => Self::Io,
        }
    }
}

impl From<SharedFileMemoryError> for WriteError {
    fn from(error: SharedFileMemoryError) -> Self {
        match error {
            SharedFileMemoryError::Fault => litebox_platform::buffer::Fault.into(),
            SharedFileMemoryError::NoMemory => Self::NoSpace,
            _ => Self::Io,
        }
    }
}

impl From<SharedFileMemoryError> for TruncateError {
    fn from(error: SharedFileMemoryError) -> Self {
        match error {
            SharedFileMemoryError::Busy => Self::Busy,
            SharedFileMemoryError::NoMemory => Self::NoSpace,
            _ => Self::Io,
        }
    }
}

impl From<SharedFileMemoryError> for MapSharedError {
    fn from(error: SharedFileMemoryError) -> Self {
        match error {
            SharedFileMemoryError::NoMemory => Self::NoMemory,
            SharedFileMemoryError::Unsupported => Self::Unsupported,
            _ => Self::Io,
        }
    }
}

/// A host handle to a [`SharedFileObject`], such as a descriptor on Linux or a `HANDLE` on
/// Windows, which is closed when this value is dropped.
pub trait HostHandle: Send {
    /// Returns the raw host handle.
    fn raw(&self) -> u64;
}

/// A host object whose pages are one file's contents.
///
/// Its size is the file's size.
pub trait SharedFileObject: Send + Sync {
    /// Returns a host handle for exporting the object, writable only if `writable` is set.
    fn host_handle(
        &self,
        writable: bool,
    ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError>;
}

/// Host memory that holds one file's contents and serves as the backend's storage.
pub trait SharedFileMemory: SharedFileObject {
    /// Copies bytes from `offset` into `buffer`, returning how many were copied, which is fewer
    /// than `buffer.len()` only at the end of the memory.
    fn read_at(
        &self,
        offset: usize,
        buffer: &mut dyn ReadBuffer,
    ) -> Result<usize, SharedFileMemoryError>;

    /// Copies `data` to `offset`, growing the memory with zeros to end there if it is shorter,
    /// and returns how many bytes were copied.
    ///
    /// This returns fewer than `data.len()` bytes when an error stops the copy
    /// after some bytes were written, which may have grown the memory to end after them; it
    /// fails only if nothing was written, leaving the size unchanged.
    fn write_at(
        &self,
        offset: usize,
        data: &dyn WriteBuffer,
    ) -> Result<usize, SharedFileMemoryError>;

    /// Returns the size in bytes, including size changes made through an exported handle.
    fn size(&self) -> Result<usize, SharedFileMemoryError>;

    /// Changes the size to `length` bytes, zero-filling any added bytes.
    fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError>;
}

/// Platform provider that creates [`SharedFileMemory`].
pub trait SharedFileMemoryProvider: Send + Sync {
    /// Creates memory of `contents.len()` bytes that initially holds `contents`.
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError>;
}

/// The default for how many files may keep their contents in host shared memory at once.
pub const DEFAULT_MAX_SHARED_FILES: usize = 256;

/// Bounds how many files keep their contents in host shared memory at once.
#[derive(Debug)]
pub struct SharedFileLimit {
    live: AtomicUsize,
    max: usize,
}

impl SharedFileLimit {
    /// Allows up to `max` files at once.
    pub const fn new(max: usize) -> Self {
        Self {
            live: AtomicUsize::new(0),
            max,
        }
    }

    /// Reserves room for one more file, or returns `None` if `max` files already hold some.
    pub fn reserve(self: &Arc<Self>) -> Option<SharedFileSlot> {
        crate::quota::try_increment(&self.live, self.max).then(|| SharedFileSlot(Arc::clone(self)))
    }

    /// Returns how many files hold host shared memory now.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }
}

/// Room for one file in a [`SharedFileLimit`], released when dropped.
#[derive(Debug)]
pub struct SharedFileSlot(Arc<SharedFileLimit>);

impl Drop for SharedFileSlot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A file's host shared object, retained by its backend and callers that request it.
pub struct SharedFile {
    object: Arc<dyn SharedFileObject>,
    _slot: SharedFileSlot,
}

impl SharedFile {
    /// Shares a file through `object`, counted against a limit by `slot`.
    pub fn new(object: Arc<dyn SharedFileObject>, slot: SharedFileSlot) -> Self {
        Self {
            object,
            _slot: slot,
        }
    }

    /// Returns the host object holding the file's contents.
    pub fn object(&self) -> &Arc<dyn SharedFileObject> {
        &self.object
    }
}

/// A file's host shared object as one descriptor may map it.
pub struct SharedMapping {
    /// The file's host shared object.
    pub file: Arc<SharedFile>,
    /// Whether the descriptor may map the object writable.
    pub writable: bool,
}

#[cfg(test)]
pub(crate) mod test_memory {
    //! A [`SharedFileMemory`] in an ordinary vector, for tests.

    use super::{
        HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
        SharedFileObject,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
    use spin::mutex::SpinMutex as Mutex;

    /// How many bytes [`VecMemory`] copies at a time, so tests can stop a write partway as hosts
    /// that write in chunks may.
    const CHUNK_SIZE: usize = 2;

    struct VecMemory {
        data: Mutex<Vec<u8>>,
        refuse_shrink: bool,
        capacity: usize,
    }

    impl VecMemory {
        /// Writes one chunk to `memory`, growing it to end after the chunk.
        fn write_chunk(
            &self,
            memory: &mut Vec<u8>,
            offset: usize,
            data: &dyn WriteBuffer,
            written: usize,
        ) -> Result<usize, SharedFileMemoryError> {
            let mut staged = [0; CHUNK_SIZE];
            let staged = &mut staged[..CHUNK_SIZE.min(data.len() - written)];
            data.copy_to_slice_at(written, staged)?;
            let start = offset + written;
            let end = start + staged.len();
            if end > self.capacity {
                return Err(SharedFileMemoryError::NoMemory);
            }
            if end > memory.len() {
                memory.resize(end, 0);
            }
            memory[start..end].copy_from_slice(staged);
            Ok(staged.len())
        }
    }

    impl SharedFileObject for VecMemory {
        fn host_handle(
            &self,
            _writable: bool,
        ) -> Result<Box<dyn HostHandle + '_>, SharedFileMemoryError> {
            Err(SharedFileMemoryError::Unsupported)
        }
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
        ) -> Result<usize, SharedFileMemoryError> {
            let mut memory = self.data.lock();
            let mut written = 0;
            while written < data.len() {
                match self.write_chunk(&mut memory, offset, data, written) {
                    Ok(count) => written += count,
                    Err(_) if written > 0 => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(written)
        }

        fn size(&self) -> Result<usize, SharedFileMemoryError> {
            Ok(self.data.lock().len())
        }

        fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError> {
            let mut data = self.data.lock();
            if self.refuse_shrink && length < data.len() {
                return Err(SharedFileMemoryError::Busy);
            }
            if length > self.capacity {
                return Err(SharedFileMemoryError::NoMemory);
            }
            data.resize(length, 0);
            Ok(())
        }
    }

    /// Creates vector memory, and remembers it for tests to access as a runner would.
    pub(crate) struct VecMemoryProvider {
        refuse_shrink: bool,
        capacity: usize,
        created: Mutex<Vec<Arc<dyn SharedFileMemory>>>,
    }

    impl VecMemoryProvider {
        /// Creates memory that refuses to shrink if `refuse_shrink` is set.
        pub(crate) fn new(refuse_shrink: bool) -> Self {
            Self {
                refuse_shrink,
                capacity: usize::MAX,
                created: Mutex::new(Vec::new()),
            }
        }

        /// Makes memory run out of space when growing past `capacity` bytes.
        pub(crate) fn with_capacity(mut self, capacity: usize) -> Self {
            self.capacity = capacity;
            self
        }

        /// Returns the memory created last.
        pub(crate) fn last(&self) -> Arc<dyn SharedFileMemory> {
            Arc::clone(self.created.lock().last().expect("no memory was created"))
        }
    }

    impl SharedFileMemoryProvider for VecMemoryProvider {
        fn create(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError> {
            let memory: Arc<dyn SharedFileMemory> = Arc::new(VecMemory {
                data: Mutex::new(contents.to_vec()),
                refuse_shrink: self.refuse_shrink,
                capacity: self.capacity,
            });
            self.created.lock().push(Arc::clone(&memory));
            Ok(memory)
        }
    }
}
