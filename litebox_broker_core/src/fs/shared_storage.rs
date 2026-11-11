// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File storage in host shared memory, which makes a file's contents mappable.
//!
//! A backend moves a file's contents into [`SharedFileMemory`] the first time
//! [`Backend::map_shared`](super::backend::Backend::map_shared) is called, by replacing the file's
//! [`FileStorageMut`] with a [`SharedStorage`]. Subsequent reads, writes, and truncations use that
//! storage, and requests for the object return the same [`SharedFile`]. Exporting the object's
//! [`HostHandle`] and mapping it are left to the caller.
//!
//! [`SharedFileLimit`] bounds how many files hold host resources at once.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use litebox_platform::buffer::{ReadBuffer, WriteBuffer};

use super::errors::{MapSharedError, StorageError};
use super::storage::{FileStorage, FileStorageMut};

impl From<StorageError> for MapSharedError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NoSpace => Self::NoMemory,
            StorageError::Fault | StorageError::Busy | StorageError::Io => Self::Io,
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
    fn host_handle(&self, writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError>;
}

/// Host memory that holds one file's contents, as two views of the same host object.
pub struct SharedFileMemory {
    /// The view the backend reads and writes, owned by the file alone.
    ///
    /// Its length includes size changes made through an exported handle.
    pub storage: Box<dyn FileStorageMut>,
    /// The view shared with callers that map the file.
    pub object: Arc<dyn SharedFileObject>,
}

/// Platform provider that creates [`SharedFileMemory`].
pub trait SharedFileMemoryProvider: Send + Sync {
    /// Creates empty memory.
    fn create(&self) -> Result<SharedFileMemory, StorageError>;
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

/// The most bytes [`SharedStorage::new`] copies at once.
const COPY_CHUNK_SIZE: usize = 64 * 1024;

/// A file's [`FileStorageMut`] once its contents are in host shared memory.
pub struct SharedStorage {
    /// The view the backend reads and writes.
    storage: Box<dyn FileStorageMut>,
    /// The shareable view of the same memory handed to callers, which also holds its slot in a
    /// [`SharedFileLimit`].
    file: Arc<SharedFile>,
}

impl SharedStorage {
    /// Moves the contents of `storage` into new memory from `provider`, counted against a limit
    /// by `slot`.
    pub fn new(
        storage: &dyn FileStorage,
        provider: &dyn SharedFileMemoryProvider,
        slot: SharedFileSlot,
    ) -> Result<Self, MapSharedError> {
        let SharedFileMemory {
            storage: mut memory,
            object,
        } = provider.create()?;
        let len = storage.len()?;
        let mut staging = crate::transfer::bounce_buffer(COPY_CHUNK_SIZE.min(len))
            .map_err(|_| MapSharedError::NoMemory)?;
        let mut offset = 0;
        while offset < len {
            let length = staging.len().min(len - offset);
            let mut chunk = &mut staging[..length];
            if storage.read_exact_at(offset, &mut chunk)? != length {
                return Err(MapSharedError::Io);
            }
            let mut written = 0;
            while written < length {
                match memory.write_at(offset + written, &&chunk[written..])? {
                    0 => return Err(MapSharedError::Io),
                    count => written += count,
                }
            }
            offset += length;
        }
        Ok(Self {
            storage: memory,
            file: Arc::new(SharedFile::new(object, slot)),
        })
    }

    /// Returns the host object that holds the contents.
    pub fn file(&self) -> &Arc<SharedFile> {
        &self.file
    }
}

impl FileStorage for SharedStorage {
    fn len(&self) -> Result<usize, StorageError> {
        self.storage.len()
    }

    fn read_at(&self, offset: usize, buf: &mut dyn ReadBuffer) -> Result<usize, StorageError> {
        self.storage.read_at(offset, buf)
    }
}

impl FileStorageMut for SharedStorage {
    fn write_at(&mut self, offset: usize, buf: &dyn WriteBuffer) -> Result<usize, StorageError> {
        self.storage.write_at(offset, buf)
    }

    fn set_len(&mut self, len: usize) -> Result<(), StorageError> {
        self.storage.set_len(len)
    }
}

#[cfg(test)]
pub(crate) mod test_memory {
    //! [`SharedFileMemory`] in an ordinary vector, for tests.

    use super::{HostHandle, SharedFileMemory, SharedFileMemoryProvider, SharedFileObject};
    use crate::fs::errors::{MapSharedError, StorageError};
    use crate::fs::storage::{FileStorage, FileStorageMut};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
    use spin::mutex::SpinMutex as Mutex;

    /// How many bytes [`VecMemory`] copies at a time, so tests can stop a write partway as hosts
    /// that write in chunks may.
    const CHUNK_SIZE: usize = 2;

    /// A vector shared by the storage, the object, and tests, which access it as a runner would.
    pub(crate) struct VecMemory {
        data: Mutex<Vec<u8>>,
        refuse_shrink: bool,
        capacity: usize,
    }

    impl VecMemory {
        /// Returns the contents.
        pub(crate) fn contents(&self) -> Vec<u8> {
            self.data.lock().clone()
        }

        /// Writes one chunk to `memory`, growing it to end after the chunk.
        fn write_chunk(
            &self,
            memory: &mut Vec<u8>,
            offset: usize,
            data: &dyn WriteBuffer,
            written: usize,
        ) -> Result<usize, StorageError> {
            let mut staged = [0; CHUNK_SIZE];
            let staged = &mut staged[..CHUNK_SIZE.min(data.len() - written)];
            data.copy_to_slice_at(written, staged)?;
            let start = offset + written;
            let end = start + staged.len();
            if end > self.capacity {
                return Err(StorageError::NoSpace);
            }
            if end > memory.len() {
                memory.resize(end, 0);
            }
            memory[start..end].copy_from_slice(staged);
            Ok(staged.len())
        }

        /// Writes as [`FileStorageMut::write_at`] does.
        pub(crate) fn write_at(
            &self,
            offset: usize,
            buf: &dyn WriteBuffer,
        ) -> Result<usize, StorageError> {
            let mut memory = self.data.lock();
            let mut written = 0;
            while written < buf.len() {
                match self.write_chunk(&mut memory, offset, buf, written) {
                    Ok(count) => written += count,
                    Err(_) if written > 0 => break,
                    Err(error) => return Err(error),
                }
            }
            Ok(written)
        }

        /// Resizes as [`FileStorageMut::set_len`] does.
        pub(crate) fn set_len(&self, len: usize) -> Result<(), StorageError> {
            let mut data = self.data.lock();
            if self.refuse_shrink && len < data.len() {
                return Err(StorageError::Busy);
            }
            if len > self.capacity {
                return Err(StorageError::NoSpace);
            }
            data.resize(len, 0);
            Ok(())
        }
    }

    struct VecStorage(Arc<VecMemory>);

    impl FileStorage for VecStorage {
        fn len(&self) -> Result<usize, StorageError> {
            Ok(self.0.data.lock().len())
        }

        fn read_at(&self, offset: usize, buf: &mut dyn ReadBuffer) -> Result<usize, StorageError> {
            let data = self.0.data.lock();
            let start = offset.min(data.len());
            let end = offset.saturating_add(buf.len()).min(data.len());
            buf.copy_from_slice_at(0, &data[start..end])?;
            Ok(end - start)
        }
    }

    impl FileStorageMut for VecStorage {
        fn write_at(
            &mut self,
            offset: usize,
            buf: &dyn WriteBuffer,
        ) -> Result<usize, StorageError> {
            self.0.write_at(offset, buf)
        }

        fn set_len(&mut self, len: usize) -> Result<(), StorageError> {
            self.0.set_len(len)
        }
    }

    struct VecObject;

    impl SharedFileObject for VecObject {
        fn host_handle(&self, _writable: bool) -> Result<Box<dyn HostHandle + '_>, MapSharedError> {
            Err(MapSharedError::Unsupported)
        }
    }

    /// Creates vector memory, and remembers it for tests to access as a runner would.
    pub(crate) struct VecMemoryProvider {
        refuse_shrink: bool,
        capacity: usize,
        created: Mutex<Vec<Arc<VecMemory>>>,
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
        pub(crate) fn last(&self) -> Arc<VecMemory> {
            Arc::clone(self.created.lock().last().expect("no memory was created"))
        }
    }

    impl SharedFileMemoryProvider for VecMemoryProvider {
        fn create(&self) -> Result<SharedFileMemory, StorageError> {
            let memory = Arc::new(VecMemory {
                data: Mutex::new(Vec::new()),
                refuse_shrink: self.refuse_shrink,
                capacity: self.capacity,
            });
            self.created.lock().push(Arc::clone(&memory));
            Ok(SharedFileMemory {
                storage: Box::new(VecStorage(memory)),
                object: Arc::new(VecObject),
            })
        }
    }
}
