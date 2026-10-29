// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host objects holding file contents, so that runners can map files without copying them.
//!
//! A backend that can share a file's pages returns a [`SharedFile`] from
//! [`Backend::map_shared`](super::backend::Backend::map_shared): a [`SharedFileObject`] whose
//! pages are the file's contents, which the deployment delivers to runners out of band through a
//! [`HostHandle`], and the ID naming it for futexes. Every runner that maps the file maps the
//! same host pages, so mappings and file I/O stay coherent without copying anything back.
//!
//! A backend whose files live in memory moves a file's contents into a [`SharedFileMemory`],
//! which is such an object that the backend also reads and writes, the first time a runner maps
//! the file. The deployment creates it (for example, as a memfd) through a
//! [`SharedFileMemoryProvider`]. The broker core never maps these objects itself.
//!
//! A backend whose files never change, such as a tar archive, instead copies a file's contents
//! once into a sealed snapshot, from [`SharedFileMemoryProvider::create_sealed`], which runners
//! map read-only or `MAP_PRIVATE`.
//!
//! Each such file holds host resources, such as broker descriptors, for as long as the file
//! exists, which may be longer than any process that mapped it. A [`SharedFileLimit`] bounds how
//! many files hold them at once, so that no guest can exhaust them for the others, and a
//! [`SnapshotLimit`] bounds the snapshots, which live as long as the broker.

use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::mutex::SpinMutex;

use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Once;
use thiserror::Error;

/// Error accessing, creating, or exporting a host object holding a file's contents.
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
    /// The host cannot provide a handle to the object with the requested rights, so the file
    /// cannot be shared.
    #[error("host cannot provide a handle to the object")]
    Unsupported,
}

impl From<litebox_platform::buffer::Fault> for SharedFileMemoryError {
    fn from(_: litebox_platform::buffer::Fault) -> Self {
        Self::Fault
    }
}

/// A host handle to a [`SharedFileObject`], such as a descriptor on Linux or a `HANDLE` on
/// Windows, which the object lends for as long as it is borrowed.
#[derive(Clone, Copy, Debug)]
pub struct HostHandle<'object> {
    raw: u64,
    _object: PhantomData<&'object ()>,
}

impl HostHandle<'_> {
    /// Lends the host handle `raw`.
    ///
    /// # Safety
    ///
    /// `raw` must name a host handle that stays open for as long as the returned value lives.
    pub unsafe fn borrow_raw(raw: u64) -> Self {
        Self {
            raw,
            _object: PhantomData,
        }
    }

    /// Returns the raw host handle, which stays open for as long as `self` lives.
    pub fn raw(self) -> u64 {
        self.raw
    }
}

/// A host object whose pages are one file's contents, which every runner that maps the file
/// maps.
///
/// Its size is the file's size: a runner accessing a mapping past it faults, as Linux raises
/// `SIGBUS` past the end of a mapped file.
pub trait SharedFileObject: Send + Sync {
    /// Returns a host handle to the object for delivering it to a runner, which may map it
    /// writable only if `writable` is set.
    ///
    /// The handle's own rights enforce `writable` where the host checks them when mapping, as
    /// for a descriptor; otherwise the deployment derives what it delivers, such as a section,
    /// with those rights.
    ///
    /// Fails with [`SharedFileMemoryError::Unsupported`] if the host cannot provide such a
    /// handle.
    fn host_handle(&self, writable: bool) -> Result<HostHandle<'_>, SharedFileMemoryError>;
}

/// Host memory that holds one file's contents, which the backend reads and writes as the file's
/// storage, and which runners map as its [`SharedFileObject`].
pub trait SharedFileMemory: SharedFileObject {
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
}

/// Creates [`SharedFileMemory`] for a deployment.
pub trait SharedFileMemoryProvider: Send + Sync {
    /// Creates memory of `contents.len()` bytes that initially holds `contents`.
    fn create(&self, contents: &[u8]) -> Result<Arc<dyn SharedFileMemory>, SharedFileMemoryError>;

    /// Creates an object holding a snapshot of `contents` that nobody, the broker included, can
    /// ever change, for runners to map read-only or `MAP_PRIVATE`.
    ///
    /// The host must enforce that the snapshot stays unchanged, as Linux does for a sealed
    /// memfd, since a runner that could change it would change every other runner's view of the
    /// file.
    ///
    /// The default implementation returns [`SharedFileMemoryError::Unsupported`].
    #[expect(unused_variables, reason = "default body, non-underscored param names")]
    fn create_sealed(
        &self,
        contents: &[u8],
    ) -> Result<Arc<dyn SharedFileObject>, SharedFileMemoryError> {
        Err(SharedFileMemoryError::Unsupported)
    }
}

/// The default for how many files may keep their contents in host shared memory at once.
pub const DEFAULT_MAX_SHARED_FILES: usize = 256;

/// Bounds how many files keep their contents in host shared memory at once.
///
/// Backends that share one limit share its bound, so a deployment makes it broker-wide by
/// passing every backend the same limit.
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
        self.live
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |live| {
                live.checked_add(1).filter(|next| *next <= self.max)
            })
            .ok()?;
        Some(SharedFileSlot(Arc::clone(self)))
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

/// The default for how many files may have a snapshot at once. See [`SnapshotLimit`].
pub const DEFAULT_MAX_SNAPSHOT_FILES: usize = 1024;
/// The default for how many bytes, rounded up to whole pages per file, snapshots may hold at
/// once. See [`SnapshotLimit`].
pub const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 1 << 30;
/// The default for the largest file that gets a snapshot. See [`SnapshotLimit`].
pub const DEFAULT_MAX_SNAPSHOT_FILE_BYTES: usize = 64 << 20;

/// Bounds the sealed snapshots that backends whose files never change keep, which live as long
/// as the broker.
///
/// A file past these bounds gets no snapshot, so runners copy it instead, as they would without
/// any; it is not an error. Backends that share one limit share its bounds.
#[derive(Debug)]
pub struct SnapshotLimit {
    /// How many files and how many page-rounded bytes snapshots hold now.
    live: SpinMutex<(usize, usize)>,
    max_files: usize,
    max_bytes: usize,
    max_file_bytes: usize,
}

/// The granularity in which [`SnapshotLimit`] counts a snapshot's bytes, as the host maps it.
const SNAPSHOT_PAGE_SIZE: usize = 4096;

impl SnapshotLimit {
    /// Allows up to `max_files` snapshots holding up to `max_bytes` in all, of files of up to
    /// `max_file_bytes` each.
    pub const fn new(max_files: usize, max_bytes: usize, max_file_bytes: usize) -> Self {
        Self {
            live: SpinMutex::new((0, 0)),
            max_files,
            max_bytes,
            max_file_bytes,
        }
    }

    /// Reserves room for a snapshot of `len` bytes for good, or returns `false` if it does not
    /// fit.
    pub fn reserve(&self, len: usize) -> bool {
        if len > self.max_file_bytes {
            return false;
        }
        let Some(bytes) = len.checked_next_multiple_of(SNAPSHOT_PAGE_SIZE) else {
            return false;
        };
        let mut live = self.live.lock();
        let (files, total) = *live;
        match (files.checked_add(1), total.checked_add(bytes)) {
            (Some(files), Some(total)) if files <= self.max_files && total <= self.max_bytes => {
                *live = (files, total);
                true
            }
            _ => false,
        }
    }

    /// Releases room that [`Self::reserve`] reserved for a snapshot of `len` bytes, for when
    /// creating the snapshot fails.
    pub fn release(&self, len: usize) {
        let bytes = len.next_multiple_of(SNAPSHOT_PAGE_SIZE);
        let mut live = self.live.lock();
        live.0 -= 1;
        live.1 -= bytes;
    }

    /// Returns how many snapshots there are, and how many page-rounded bytes they hold.
    pub fn live(&self) -> (usize, usize) {
        *self.live.lock()
    }
}

impl Default for SnapshotLimit {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_SNAPSHOT_FILES,
            DEFAULT_MAX_SNAPSHOT_BYTES,
            DEFAULT_MAX_SNAPSHOT_FILE_BYTES,
        )
    }
}

/// A file's host shared object, which every runner mapping the file maps, as a backend shares
/// it, and the ID naming it for futexes.
pub struct SharedFile {
    object: Arc<dyn SharedFileObject>,
    /// Names the object for futexes, issued when a runner first maps the file.
    memory_id: Once<SharedMemoryId>,
    /// Counts this file against its backend's limit for as long as the file holds the object,
    /// unless a [`SnapshotLimit`] counts it instead.
    _slot: Option<SharedFileSlot>,
}

impl SharedFile {
    /// Shares a file through `object`, counted against a limit by `slot`.
    pub fn new(object: Arc<dyn SharedFileObject>, slot: SharedFileSlot) -> Self {
        Self {
            object,
            memory_id: Once::new(),
            _slot: Some(slot),
        }
    }

    /// Shares a file through the sealed snapshot `object`, which a [`SnapshotLimit`] counts.
    pub fn snapshot(object: Arc<dyn SharedFileObject>) -> Self {
        Self {
            object,
            memory_id: Once::new(),
            _slot: None,
        }
    }

    /// Returns the host object holding the file's contents.
    pub fn object(&self) -> &Arc<dyn SharedFileObject> {
        &self.object
    }

    /// Returns the ID naming the object, issuing it with `issue` the first time.
    pub(crate) fn memory_id<E>(
        &self,
        issue: impl FnOnce() -> Result<SharedMemoryId, E>,
    ) -> Result<SharedMemoryId, E> {
        self.memory_id.try_call_once(issue).copied()
    }
}

/// A file's host shared object, as returned to a runner that maps the file.
#[derive(Clone)]
pub struct SharedFileMapping {
    /// Names the object, the same for every process that maps the file.
    pub memory_id: SharedMemoryId,
    /// The host object holding the file's contents, for the deployment to deliver.
    pub object: Arc<dyn SharedFileObject>,
    /// Whether the runner may map the object writable.
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

    use super::{
        HostHandle, SharedFileMemory, SharedFileMemoryError, SharedFileMemoryProvider,
        SharedFileObject,
    };
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
    use spin::mutex::SpinMutex as Mutex;

    struct VecMemory {
        data: Mutex<Vec<u8>>,
        /// Whether shrinking fails, as on Windows while the memory is mapped.
        refuse_shrink: bool,
    }

    /// Vector memory has no host handle, so it serves the file system but cannot be delivered.
    impl SharedFileObject for VecMemory {
        fn host_handle(&self, _writable: bool) -> Result<HostHandle<'_>, SharedFileMemoryError> {
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
    }

    /// Creates vector memory, and remembers it for tests to access as a runner would.
    pub(crate) struct VecMemoryProvider {
        /// Whether the memory refuses to shrink.
        refuse_shrink: bool,
        created: Mutex<Vec<Arc<dyn SharedFileMemory>>>,
        /// The contents of every snapshot created, in order.
        sealed: Mutex<Vec<Vec<u8>>>,
    }

    impl VecMemoryProvider {
        /// Creates memory that refuses to shrink if `refuse_shrink` is set.
        pub(crate) fn new(refuse_shrink: bool) -> Self {
            Self {
                refuse_shrink,
                created: Mutex::new(Vec::new()),
                sealed: Mutex::new(Vec::new()),
            }
        }

        /// Returns the contents of every snapshot created, in order.
        pub(crate) fn sealed(&self) -> Vec<Vec<u8>> {
            self.sealed.lock().clone()
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
            });
            self.created.lock().push(Arc::clone(&memory));
            Ok(memory)
        }

        fn create_sealed(
            &self,
            contents: &[u8],
        ) -> Result<Arc<dyn SharedFileObject>, SharedFileMemoryError> {
            self.sealed.lock().push(contents.to_vec());
            Ok(Arc::new(VecMemory {
                data: Mutex::new(contents.to_vec()),
                refuse_shrink: true,
            }))
        }
    }
}
