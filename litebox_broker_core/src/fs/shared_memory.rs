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
//! A backend whose files never change, such as a tar archive, shares a file from a host object
//! that holds the whole archive, through an [`ObjectWindow`] naming where the file lies in it, if
//! the deployment gives it one and the file is page-aligned in it. Otherwise it copies the file's
//! contents once into a sealed snapshot, from [`SharedFileMemoryProvider::create_sealed`]. Runners
//! map either read-only or `MAP_PRIVATE`.
//!
//! Each such file holds host resources, such as broker descriptors. Every process that maps a
//! file holds a lease on it until the process ends, since it may map the file until then, and a
//! [`SharedFileLimit`] bounds how many files hold host resources at once, reclaiming the least
//! recently used files that nothing refers to, leased or otherwise, to make room. A
//! [`SnapshotLimit`] bounds the snapshots, which live as long as the broker and so need no
//! lease.

use alloc::boxed::Box;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::mutex::SpinMutex;

use litebox_broker_protocol::fs::ObjectWindow;
use litebox_broker_protocol::shared_futex::SharedMemoryId;
use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
use spin::Once;
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

/// A host object whose pages are one file's contents, which every runner that maps the file
/// maps.
///
/// Its size is the file's size: a runner accessing a mapping past it faults, as Linux raises
/// `SIGBUS` past the end of a mapped file.
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

    /// Returns the size in bytes.
    ///
    /// A runner that may map the memory writable may also be able to grow it, so the broker
    /// asks the memory rather than remembering the size, as if the runner had extended the
    /// file, which it may write anyway.
    fn size(&self) -> Result<usize, SharedFileMemoryError>;

    /// Changes the size to `length` bytes, zero-filling any added bytes.
    fn set_len(&self, length: usize) -> Result<(), SharedFileMemoryError>;
}

/// Platform provider that creates [`SharedFileMemory`].
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

/// A backend's file whose contents a [`SharedFile`] may hold in host shared memory, and which
/// can move them back into broker memory.
pub trait Reclaim: Send + Sync {
    /// Moves the file's contents back into broker memory and drops `file`, if the file's
    /// contents are still in `file` and nothing but the file refers to `file` or its memory,
    /// returning whether it did.
    ///
    /// Process leases, deliveries in progress, and accesses in progress all refer to them, so a
    /// file that any runner may still map is never reclaimed.
    fn reclaim(&self, file: &Weak<SharedFile>) -> bool;
}

/// Bounds how many files keep their contents in host shared memory at once.
///
/// A file that needs room when there is none reclaims the least recently used files that no
/// runner may still map, moving their contents back into broker memory.
pub struct SharedFileLimit {
    live: AtomicUsize,
    max: usize,
    /// Every file whose contents may be in host shared memory, with the backend file holding
    /// them, so that they can be reclaimed.
    files: SpinMutex<Vec<Registered>>,
    /// Counts uses of files, so that each records when it was last used.
    clock: AtomicUsize,
}

/// A file that a [`SharedFileLimit`] may reclaim, and the backend file holding it.
struct Registered {
    file: Weak<SharedFile>,
    owner: Weak<dyn Reclaim>,
}

impl SharedFileLimit {
    /// Allows up to `max` files at once.
    pub const fn new(max: usize) -> Self {
        Self {
            live: AtomicUsize::new(0),
            max,
            files: SpinMutex::new(Vec::new()),
            clock: AtomicUsize::new(0),
        }
    }

    /// Reserves room for one more file, reclaiming the least recently used files that no
    /// runner may still map to make it, or returns `None` if there is none.
    ///
    /// Reclaiming takes the reclaimed files' locks, so callers must not hold any backend file's
    /// lock.
    pub fn reserve(self: &Arc<Self>) -> Option<SharedFileSlot> {
        loop {
            if crate::quota::try_increment(&self.live, self.max) {
                return Some(SharedFileSlot(Arc::clone(self)));
            }
            if !self.reclaim_least_recently_used() {
                return None;
            }
        }
    }

    /// Reclaims the least recently used file that no runner may still map, returning whether
    /// there was one.
    ///
    /// Reclaiming takes the reclaimed file's lock, so callers must not hold any backend file's
    /// lock.
    pub fn reclaim_least_recently_used(&self) -> bool {
        let mut candidates: Vec<_> = {
            let mut files = self.files.lock();
            files.retain(|entry| entry.file.strong_count() > 0 && entry.owner.strong_count() > 0);
            files
                .iter()
                .filter_map(|Registered { file, owner }| {
                    // Reading the time through a weak reference would need a strong one, which
                    // would keep the file from being reclaimed, so read it now.
                    let last_use = file.upgrade()?.last_use.load(Ordering::Relaxed);
                    Some((last_use, file.clone(), owner.clone()))
                })
                .collect()
        };
        candidates.sort_unstable_by_key(|(last_use, ..)| *last_use);
        candidates
            .into_iter()
            .any(|(_, file, owner)| owner.upgrade().is_some_and(|owner| owner.reclaim(&file)))
    }

    /// Records that `file`, which `owner` holds, may hold host shared memory, so that it can
    /// be reclaimed.
    pub fn register(&self, file: &Arc<SharedFile>, owner: Weak<dyn Reclaim>) {
        self.touch(file);
        let mut files = self.files.lock();
        // Drop the entries of files gone since, so that files that come and go, such as ones
        // deleted, never grow the list past the files that hold host shared memory.
        files.retain(|entry| entry.file.strong_count() > 0 && entry.owner.strong_count() > 0);
        files.push(Registered {
            file: Arc::downgrade(file),
            owner,
        });
    }

    /// Records that `file` was just used, so that reclaiming takes it last.
    pub fn touch(&self, file: &SharedFile) {
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        file.last_use.store(now, Ordering::Relaxed);
    }

    /// Returns how many files hold host shared memory now.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Returns how many files are recorded as able to be reclaimed, including ones gone since.
    #[cfg(test)]
    pub(crate) fn registered(&self) -> usize {
        self.files.lock().len()
    }
}

impl core::fmt::Debug for SharedFileLimit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedFileLimit")
            .field("live", &self.live())
            .field("max", &self.max)
            .finish_non_exhaustive()
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
    /// Where the file lies in `object`, if the object holds more than the file.
    window: Option<ObjectWindow>,
    /// Names the object for futexes, issued when a runner first maps the file.
    memory_id: Once<SharedMemoryId>,
    /// Counts this file against its backend's limit for as long as the file holds the object,
    /// unless a [`SnapshotLimit`] counts it instead.
    slot: Option<SharedFileSlot>,
    /// When the file was last used, by its [`SharedFileLimit`]'s clock.
    last_use: AtomicUsize,
}

impl SharedFile {
    /// Shares a file through `object`, counted against a limit by `slot`.
    pub fn new(object: Arc<dyn SharedFileObject>, slot: SharedFileSlot) -> Self {
        Self {
            object,
            window: None,
            memory_id: Once::new(),
            slot: Some(slot),
            last_use: AtomicUsize::new(0),
        }
    }

    /// Shares a file through the sealed snapshot `object`, which a [`SnapshotLimit`] counts.
    pub fn snapshot(object: Arc<dyn SharedFileObject>) -> Self {
        Self {
            object,
            window: None,
            memory_id: Once::new(),
            slot: None,
            last_use: AtomicUsize::new(0),
        }
    }

    /// Shares a file that lies at `window` in `object`, which never changes, is never delivered
    /// writable, and which the backend holds for as long as it exists, so that no limit counts
    /// it.
    pub fn window(object: Arc<dyn SharedFileObject>, window: ObjectWindow) -> Self {
        Self {
            object,
            window: Some(window),
            memory_id: Once::new(),
            slot: None,
            last_use: AtomicUsize::new(0),
        }
    }

    /// Returns the host object holding the file's contents.
    pub fn object(&self) -> &Arc<dyn SharedFileObject> {
        &self.object
    }

    /// Returns where the file lies in [`Self::object`], if the object holds more than the file.
    pub fn object_window(&self) -> Option<ObjectWindow> {
        self.window
    }

    /// Returns whether runners' mappings need a lease on this file to keep its contents in the
    /// object. Snapshots and windows need none, since their objects never change and live as
    /// long as the broker.
    pub(crate) fn needs_lease(&self) -> bool {
        self.slot.is_some()
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
    /// Where the file lies in the object, if the object holds more than the file.
    pub window: Option<ObjectWindow>,
}

impl core::fmt::Debug for SharedFileMapping {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedFileMapping")
            .field("memory_id", &self.memory_id)
            .field("writable", &self.writable)
            .field("window", &self.window)
            .finish_non_exhaustive()
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
    use alloc::sync::{Arc, Weak};
    use alloc::vec::Vec;
    use litebox_platform::buffer::{ReadBuffer, WriteBuffer};
    use spin::mutex::SpinMutex as Mutex;

    /// How many bytes [`VecMemory`] copies at a time, so tests can stop a write partway as hosts
    /// that write in chunks may.
    const CHUNK_SIZE: usize = 2;

    struct VecMemory {
        data: Mutex<Vec<u8>>,
        /// Whether shrinking fails, as on Windows while the memory is mapped.
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

    /// Vector memory has no host handle, so it serves the file system but cannot be delivered.
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
        /// Whether the memory refuses to shrink.
        refuse_shrink: bool,
        capacity: usize,
        /// Every memory created, which the provider does not keep alive, as hosts do not.
        created: Mutex<Vec<Weak<dyn SharedFileMemory>>>,
        /// The contents of every snapshot created, in order.
        sealed: Mutex<Vec<Vec<u8>>>,
    }

    impl VecMemoryProvider {
        /// Creates memory that refuses to shrink if `refuse_shrink` is set.
        pub(crate) fn new(refuse_shrink: bool) -> Self {
            Self {
                refuse_shrink,
                capacity: usize::MAX,
                created: Mutex::new(Vec::new()),
                sealed: Mutex::new(Vec::new()),
            }
        }

        /// Makes memory run out of space when growing past `capacity` bytes.
        pub(crate) fn with_capacity(mut self, capacity: usize) -> Self {
            self.capacity = capacity;
            self
        }

        /// Returns the contents of every snapshot created, in order.
        pub(crate) fn sealed(&self) -> Vec<Vec<u8>> {
            self.sealed.lock().clone()
        }

        /// Returns the memory created last, while it is alive.
        pub(crate) fn last(&self) -> Arc<dyn SharedFileMemory> {
            self.created
                .lock()
                .last()
                .and_then(Weak::upgrade)
                .expect("no live memory was created last")
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
            self.created.lock().push(Arc::downgrade(&memory));
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
                capacity: contents.len(),
            }))
        }
    }
}
