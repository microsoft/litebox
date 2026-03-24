// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT object handle table.
//!
//! Maps Windows HANDLEs (opaque `usize` values) to typed kernel objects.
//! Handles are allocated as small integers starting from 4 (Windows skips 0,
//! and uses multiples of 4 for compatibility with tagged pointers).
//!
//! The handle table is not internally synchronized. The shim wraps it in a
//! `Mutex` for multi-threaded access (Phase 3+).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use litebox_common_windows::ntstatus::NtStatus;
use litebox_platform_multiplex::Platform;

/// Type alias for thread wakers used by sync object waiters.
type SyncWaker = litebox::event::wait::Waker<Platform>;

/// The first allocatable handle value. Windows handles start at 4.
const FIRST_HANDLE: u32 = 4;
/// Handle increment (Windows allocates handles in steps of 4).
const HANDLE_STEP: u32 = 4;

/// Shared file position. Duplicated handles share the same host file object
/// and therefore the same file pointer; this `Arc<AtomicU64>` ensures both
/// handles see the same cached position (thread-safe for Phase 3+).
pub type SharedFilePosition = Arc<core::sync::atomic::AtomicU64>;

/// An NT kernel object.
pub enum NtObject {
    /// Console input stream (stdin).
    ConsoleInput,
    /// Console output stream (stdout or stderr).
    ConsoleOutput {
        /// True for stderr, false for stdout.
        is_stderr: bool,
    },
    /// A file opened via NtCreateFile.
    File {
        /// Guest-visible NT path.
        path: String,
        /// Shared file position (byte offset). Cloned on DuplicateHandle so
        /// both handles track the same underlying file pointer.
        position: SharedFilePosition,
        /// VFS raw fd index into `RawDescriptorStorage`.
        raw_fd: usize,
        /// Reference count for VFS fd. Multiple NT handles may share one VFS
        /// fd (via DuplicateHandle). Only the last close actually closes the
        /// VFS fd.
        vfs_refcount: Arc<core::sync::atomic::AtomicUsize>,
    },
    /// A directory opened via NtCreateFile.
    Directory {
        /// Guest-visible NT path.
        path: String,
        /// Cached directory entries for NtQueryDirectoryFile enumeration.
        /// Populated lazily on the first query. Subsequent calls advance
        /// `enum_index` to provide forward progress.
        enum_entries: Vec<DirEnumEntry>,
        /// Current enumeration index into `enum_entries`.
        enum_index: usize,
    },
    /// A Win32 file search handle (FindFirstFileExW / FindNextFileW).
    FindSearch {
        /// All matching entries from the host search.
        entries: Vec<DirEnumEntry>,
        /// Index of the next entry to return from FindNextFileW.
        next_index: usize,
    },
    /// A placeholder for objects we don't fully implement yet.
    Stub {
        /// Description for debugging.
        kind: String,
    },
    /// An NT event object (NtCreateEvent).
    Event(Arc<EventObject>),
    /// An NT semaphore object (NtCreateSemaphore).
    Semaphore(Arc<SemaphoreObject>),
    /// An NT mutant object (NtCreateMutant).
    Mutant(Arc<MutantObject>),
    /// An NT keyed event object (NtCreateKeyedEvent).
    KeyedEvent(Arc<KeyedEventObject>),
    /// An NT thread object (NtCreateThreadEx).
    Thread(Arc<ThreadObject>),
    /// An NT I/O completion port object.
    IoCompletion(Arc<IoCompletionObject>),
    /// A WinSock socket. The actual `SocketFd` is stored in
    /// `NtSharedState::sockets`; this variant just records the key.
    Socket {
        /// Key into `NtSharedState::sockets`.
        sock_id: u32,
    },
    /// An NT section object (NtCreateSection).
    Section {
        /// The raw PE data (for SEC_IMAGE sections).
        pe_data: Arc<Vec<u8>>,
        /// Parsed PE metadata.
        image_size: u32,
        image_base: u64,
        entry_point: u32,
        section_alignment: u32,
        is_dll: bool,
    },
    /// An anonymous data section (NtCreateSection without SEC_IMAGE).
    DataSection {
        /// Maximum size of the section (in bytes).
        max_size: u64,
    },
    /// Current process handle (from duplicating pseudo-handle -1).
    CurrentProcess,
    /// Current thread handle (from duplicating pseudo-handle -2).
    CurrentThread,
    /// A registry key handle.
    RegistryKey {
        /// Canonical NT path for this key, used to resolve RootDirectory-relative opens.
        path: String,
    },
}

/// Internal state for an NT event object.
///
/// Events have two modes:
/// - **Manual-reset**: stays signaled until explicitly reset. NtSetEvent wakes
///   all waiters.
/// - **Auto-reset**: automatically resets after waking one waiter.
pub struct EventObject {
    /// Mutex-protected signaled state.
    pub state: Mutex<bool>,
    /// True = manual-reset, false = auto-reset.
    pub manual_reset: bool,
    /// Wakers for threads blocked in wait_event. Signaling paths wake
    /// all registered wakers so that `wait_until` re-evaluates.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

impl EventObject {
    /// Create a new event.
    pub fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self {
            state: Mutex::new(initial_state),
            manual_reset,
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this event.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT thread object.
///
/// Tracks thread exit status. Waiters block via WaitContext and are woken
/// when the thread exits.
pub struct ThreadObject {
    /// Thread exit code, set when the thread terminates.
    /// None = still running, Some(code) = exited.
    pub exit_status: Mutex<Option<i32>>,
    /// Guest-visible thread ID (TEB.ClientId.UniqueThread / GetCurrentThreadId).
    pub thread_id: u32,
    /// Guest VA of this thread's TEB.
    pub teb_va: Mutex<usize>,
    /// Wakers for threads blocked in wait_thread.
    pub waiters: Mutex<Vec<SyncWaker>>,
    /// Current suspend count. New threads created with CREATE_SUSPENDED start at 1.
    pub suspend_count: Mutex<u32>,
    /// Wakers for child threads blocked waiting to be resumed.
    pub resume_waiters: Mutex<Vec<SyncWaker>>,
    /// Pending alert-by-thread-id wake for NtWaitForAlertByThreadId.
    pub alert_by_id_pending: Mutex<bool>,
    /// Wakers for threads blocked in NtWaitForAlertByThreadId.
    pub alert_by_id_waiters: Mutex<Vec<SyncWaker>>,
}

impl ThreadObject {
    /// Create a new thread object with the given initial suspend count.
    pub fn new(thread_id: u32, initial_suspend_count: u32, teb_va: usize) -> Self {
        Self {
            exit_status: Mutex::new(None),
            thread_id,
            teb_va: Mutex::new(teb_va),
            waiters: Mutex::new(Vec::new()),
            suspend_count: Mutex::new(initial_suspend_count),
            resume_waiters: Mutex::new(Vec::new()),
            alert_by_id_pending: Mutex::new(false),
            alert_by_id_waiters: Mutex::new(Vec::new()),
        }
    }

    /// Mark the thread as exited with the given exit code and wake all waiters.
    pub fn set_exited(&self, code: i32) {
        *self.exit_status.lock() = Some(code);
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }

    /// Returns true if the thread has exited.
    pub fn has_exited(&self) -> bool {
        self.exit_status.lock().is_some()
    }

    /// Return the thread's current guest TEB VA.
    pub fn teb_va(&self) -> usize {
        *self.teb_va.lock()
    }

    /// Update the thread's guest TEB VA once it becomes known.
    pub fn set_teb_va(&self, teb_va: usize) {
        *self.teb_va.lock() = teb_va;
    }

    /// Block the host thread until the guest thread is resumed.
    pub fn wait_until_resumed(&self, cx: &litebox::event::wait::WaitContext<'_, Platform>) {
        self.resume_waiters.lock().push(cx.waker().clone());
        let _ = cx.wait_until(|| *self.suspend_count.lock() == 0);
        self.resume_waiters.lock().retain(|w| !w.ptr_eq(cx.waker()));
    }

    /// Resume the thread once and return the previous suspend count.
    pub fn resume(&self) -> u32 {
        let mut suspend_count = self.suspend_count.lock();
        let previous = *suspend_count;
        if *suspend_count != 0 {
            *suspend_count -= 1;
            if *suspend_count == 0 {
                let mut waiters = self.resume_waiters.lock();
                for w in waiters.drain(..) {
                    w.wake();
                }
            }
        }
        previous
    }

    /// Consume a pending alert-by-thread-id wake, if one exists.
    pub fn take_pending_alert_by_id(&self) -> bool {
        let mut pending = self.alert_by_id_pending.lock();
        if *pending {
            *pending = false;
            true
        } else {
            false
        }
    }

    /// Post an alert-by-thread-id wake and notify any blocked waiters.
    pub fn alert_by_id(&self) {
        *self.alert_by_id_pending.lock() = true;
        for w in self.alert_by_id_waiters.lock().iter() {
            w.wake();
        }
    }
}

/// A queued completion packet delivered through an I/O completion port.
#[derive(Clone, Copy, Debug)]
pub struct IoCompletionEntry {
    pub key_context: usize,
    pub apc_context: usize,
    pub status: NtStatus,
    pub information: usize,
}

/// Internal state for an NT I/O completion port.
pub struct IoCompletionObject {
    /// FIFO queue of pending completion packets.
    pub queue: Mutex<VecDeque<IoCompletionEntry>>,
    /// Wakers for threads blocked in NtRemoveIoCompletion[Ex].
    pub waiters: Mutex<Vec<SyncWaker>>,
}

impl IoCompletionObject {
    /// Create an empty completion port.
    pub fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Queue a completion packet and wake any waiting threads.
    pub fn push(&self, entry: IoCompletionEntry) {
        self.queue.lock().push_back(entry);
        self.wake_waiters();
    }

    /// Wake all threads waiting on this completion port.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT semaphore object.
pub struct SemaphoreObject {
    /// Mutex-protected current count.
    pub state: Mutex<i32>,
    /// Maximum count.
    pub max_count: i32,
    /// Wakers for threads blocked in wait_semaphore.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

impl SemaphoreObject {
    /// Create a new semaphore.
    pub fn new(initial_count: i32, max_count: i32) -> Self {
        Self {
            state: Mutex::new(initial_count),
            max_count,
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this semaphore.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT mutant object.
pub struct MutantObject {
    /// Mutex-protected owner / recursion / abandoned state.
    pub state: Mutex<MutantState>,
    /// Wakers for threads blocked waiting on this mutant.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Mutable state inside a mutant object.
#[derive(Clone, Copy, Debug, Default)]
pub struct MutantState {
    /// Owning thread, if any.
    pub owner_thread_id: Option<u32>,
    /// Recursive acquisition count for the owner.
    pub recursion_count: u32,
    /// Whether the previous owner exited without releasing.
    pub abandoned: bool,
}

impl MutantObject {
    /// Create a new mutant.
    pub fn new(initial_owner: bool, owner_thread_id: u32) -> Self {
        Self {
            state: Mutex::new(MutantState {
                owner_thread_id: initial_owner.then_some(owner_thread_id),
                recursion_count: u32::from(initial_owner),
                abandoned: false,
            }),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Wake all threads waiting on this mutant.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// Internal state for an NT keyed event object.
///
/// Keyed events are a low-level futex-like primitive used internally by
/// SRW locks and condition variables. Each wait/release pair is matched 1:1:
/// one NtReleaseKeyedEvent wakes exactly one NtWaitForKeyedEvent on the same
/// key, and vice versa.
pub struct KeyedEventObject {
    /// Per-key queue state with per-caller release tokens for 1:1 matching.
    pub state: Mutex<BTreeMap<usize, KeyedWaiterQueue>>,
    /// Monotonic counter for unique release token IDs.
    next_release_id: Mutex<u64>,
    /// Wakers for threads blocked in wait/release on this keyed event.
    pub waiters: Mutex<Vec<SyncWaker>>,
}

/// Per-key queue state inside a keyed event.
///
/// Uses a VecDeque of per-releaser tokens so that each blocked releaser
/// knows exactly when *its* release has been consumed by a waiter.
#[derive(Debug, Default)]
pub struct KeyedWaiterQueue {
    /// Number of threads currently blocked in NtWaitForKeyedEvent on this key.
    pub waiters: u32,
    /// FIFO queue of pending release tokens. Each releaser that posts before
    /// a waiter exists pushes a token and blocks until `consumed` is set.
    /// Waiters pop from the front to pair 1:1 with releasers in FIFO order.
    pub pending_releases: alloc::collections::VecDeque<ReleaseToken>,
    /// Number of releases that have been matched to a waiter but the waiter
    /// hasn't consumed yet (used when a releaser finds a blocked waiter and
    /// returns immediately — the waiter side decrements this).
    pub ready: u32,
}

/// A per-releaser token in the pending release queue.
#[derive(Debug)]
pub struct ReleaseToken {
    /// Unique ID for this release, used by the releaser to detect when
    /// *its specific* release has been consumed.
    pub id: u64,
    /// Set to true by the waiter that consumes this release.
    pub consumed: bool,
}

impl KeyedWaiterQueue {
    /// Returns true if the queue is empty and can be removed.
    pub fn is_empty(&self) -> bool {
        self.waiters == 0 && self.pending_releases.is_empty() && self.ready == 0
    }
}

impl KeyedEventObject {
    /// Create a new keyed event.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BTreeMap::new()),
            next_release_id: Mutex::new(0),
            waiters: Mutex::new(Vec::new()),
        }
    }

    /// Allocate a unique release token ID.
    pub fn alloc_release_id(&self) -> u64 {
        let mut id = self.next_release_id.lock();
        let val = *id;
        *id = val.wrapping_add(1);
        val
    }

    /// Wake all threads waiting on this keyed event.
    pub fn wake_waiters(&self) {
        for w in self.waiters.lock().iter() {
            w.wake();
        }
    }
}

/// A cached directory/search entry.
#[derive(Debug, Clone)]
pub struct DirEnumEntry {
    pub name: String,
    pub attributes: u32,
    pub file_size: i64,
    pub creation_time: i64,
    pub last_access_time: i64,
    pub last_write_time: i64,
}

/// The NT handle table.
///
/// Thread-safety: The handle table is not internally synchronized. The shim
/// must ensure single-threaded access (Phase 1) or wrap in a Mutex (Phase 3+).
pub struct HandleTable {
    /// Map from handle value to object.
    objects: BTreeMap<u32, NtObject>,
    /// Next handle value to allocate.
    next_handle: u32,
}

impl HandleTable {
    /// Create a new empty handle table.
    pub fn new() -> Self {
        Self {
            objects: BTreeMap::new(),
            next_handle: FIRST_HANDLE,
        }
    }

    /// Create a handle table pre-populated with standard console handles.
    ///
    /// Returns (table, stdin_handle, stdout_handle, stderr_handle).
    pub fn with_stdio() -> (Self, u32, u32, u32) {
        let mut table = Self::new();
        let stdin = table.insert(NtObject::ConsoleInput);
        let stdout = table.insert(NtObject::ConsoleOutput { is_stderr: false });
        let stderr = table.insert(NtObject::ConsoleOutput { is_stderr: true });
        (table, stdin, stdout, stderr)
    }

    /// Allocate a new handle for the given object.
    pub fn insert(&mut self, object: NtObject) -> u32 {
        let handle = self.next_handle;
        self.objects.insert(handle, object);
        self.next_handle += HANDLE_STEP;
        handle
    }

    /// Look up an object by handle.
    pub fn get(&self, handle: u32) -> Option<&NtObject> {
        self.objects.get(&handle)
    }

    /// Iterate all objects currently stored in the table.
    pub fn values(&self) -> impl Iterator<Item = &NtObject> + '_ {
        self.objects.values()
    }

    /// Look up an object by handle (mutable).
    pub fn get_mut(&mut self, handle: u32) -> Option<&mut NtObject> {
        self.objects.get_mut(&handle)
    }

    /// Close a handle, returning the object if it existed.
    pub fn close(&mut self, handle: u32) -> Option<NtObject> {
        self.objects.remove(&handle)
    }

    /// Returns true if the handle exists in the table.
    pub fn contains(&self, handle: u32) -> bool {
        self.objects.contains_key(&handle)
    }

    /// Duplicate a handle, creating a new handle table entry pointing to
    /// the same underlying object. For VFS File objects, the `Arc` position
    /// and refcount are shared so both handles see the same file state.
    /// Returns the new handle, or `None` if the source doesn't exist.
    pub fn duplicate(&mut self, source: u32) -> Option<u32> {
        let obj = self.objects.get(&source)?;
        let new_obj = match obj {
            NtObject::ConsoleInput => NtObject::ConsoleInput,
            NtObject::ConsoleOutput { is_stderr } => NtObject::ConsoleOutput {
                is_stderr: *is_stderr,
            },
            NtObject::File {
                path,
                position,
                raw_fd,
                vfs_refcount,
            } => {
                // VFS-backed file: share the same raw_fd and bump refcount.
                vfs_refcount.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                NtObject::File {
                    path: path.clone(),
                    position: Arc::clone(position),
                    raw_fd: *raw_fd,
                    vfs_refcount: Arc::clone(vfs_refcount),
                }
            }
            NtObject::Directory { path, .. } => NtObject::Directory {
                path: path.clone(),
                enum_entries: Vec::new(),
                enum_index: 0,
            },
            NtObject::FindSearch { entries, .. } => NtObject::FindSearch {
                entries: entries.clone(),
                next_index: 0,
            },
            NtObject::Stub { kind } => NtObject::Stub { kind: kind.clone() },
            NtObject::Event(e) => NtObject::Event(Arc::clone(e)),
            NtObject::Semaphore(s) => NtObject::Semaphore(Arc::clone(s)),
            NtObject::Mutant(m) => NtObject::Mutant(Arc::clone(m)),
            NtObject::KeyedEvent(k) => NtObject::KeyedEvent(Arc::clone(k)),
            NtObject::Thread(t) => NtObject::Thread(Arc::clone(t)),
            NtObject::IoCompletion(port) => NtObject::IoCompletion(Arc::clone(port)),
            NtObject::Socket { sock_id } => NtObject::Socket { sock_id: *sock_id },
            NtObject::Section {
                pe_data,
                image_size,
                image_base,
                entry_point,
                section_alignment,
                is_dll,
            } => NtObject::Section {
                pe_data: Arc::clone(pe_data),
                image_size: *image_size,
                image_base: *image_base,
                entry_point: *entry_point,
                section_alignment: *section_alignment,
                is_dll: *is_dll,
            },
            NtObject::DataSection { max_size } => NtObject::DataSection {
                max_size: *max_size,
            },
            NtObject::CurrentProcess => NtObject::CurrentProcess,
            NtObject::CurrentThread => NtObject::CurrentThread,
            NtObject::RegistryKey { path } => NtObject::RegistryKey { path: path.clone() },
        };
        Some(self.insert(new_obj))
    }

    /// Returns all active handles (for debugging).
    pub fn handles(&self) -> Vec<u32> {
        self.objects.keys().copied().collect()
    }
}

impl Default for HandleTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_handle_operations() {
        let mut table = HandleTable::new();

        let h1 = table.insert(NtObject::ConsoleInput);
        let h2 = table.insert(NtObject::ConsoleOutput { is_stderr: false });

        assert_eq!(h1, 4);
        assert_eq!(h2, 8);

        assert!(table.get(h1).is_some());
        assert!(table.get(h2).is_some());
        assert!(table.get(99).is_none());

        let removed = table.close(h1);
        assert!(removed.is_some());
        assert!(table.get(h1).is_none());
    }

    #[test]
    fn stdio_handles() {
        let (table, stdin, stdout, stderr) = HandleTable::with_stdio();

        assert!(matches!(table.get(stdin), Some(NtObject::ConsoleInput)));
        assert!(matches!(
            table.get(stdout),
            Some(NtObject::ConsoleOutput { is_stderr: false })
        ));
        assert!(matches!(
            table.get(stderr),
            Some(NtObject::ConsoleOutput { is_stderr: true })
        ));
    }
}
