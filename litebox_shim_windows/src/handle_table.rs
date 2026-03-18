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

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::{Condvar, Mutex};

/// The first allocatable handle value. Windows handles start at 4.
const FIRST_HANDLE: u32 = 4;
/// Handle increment (Windows allocates handles in steps of 4).
const HANDLE_STEP: u32 = 4;

/// Shared file position. Duplicated handles share the same host file object
/// and therefore the same file pointer; this `Arc<AtomicU64>` ensures both
/// handles see the same cached position (thread-safe for Phase 3+).
pub type SharedFilePosition = Arc<core::sync::atomic::AtomicU64>;

/// An NT kernel object.
#[derive(Debug)]
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
        /// Host file handle (Windows HANDLE as usize). 0 = invalid.
        host_handle: usize,
        /// Shared file position (byte offset). Cloned on DuplicateHandle so
        /// both handles track the same underlying file pointer.
        position: SharedFilePosition,
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
    /// An NT keyed event object (NtCreateKeyedEvent).
    KeyedEvent(Arc<KeyedEventObject>),
    /// An NT thread object (NtCreateThreadEx).
    Thread(Arc<ThreadObject>),
}

/// Internal state for an NT event object.
///
/// Events have two modes:
/// - **Manual-reset**: stays signaled until explicitly reset. NtSetEvent wakes
///   all waiters.
/// - **Auto-reset**: automatically resets after waking one waiter.
#[derive(Debug)]
pub struct EventObject {
    /// Mutex-protected signaled state.
    pub state: Mutex<bool>,
    /// Condvar for waiters to block on.
    pub condvar: Condvar,
    /// True = manual-reset, false = auto-reset.
    pub manual_reset: bool,
}

impl EventObject {
    /// Create a new event.
    pub fn new(manual_reset: bool, initial_state: bool) -> Self {
        Self {
            state: Mutex::new(initial_state),
            condvar: Condvar::new(),
            manual_reset,
        }
    }
}

/// Internal state for an NT thread object.
///
/// Tracks thread exit status and provides a condvar for WaitForSingleObject
/// on thread handles.
#[derive(Debug)]
pub struct ThreadObject {
    /// Thread exit code, set when the thread terminates.
    /// None = still running, Some(code) = exited.
    pub exit_status: Mutex<Option<i32>>,
    /// Condvar signaled when the thread exits.
    pub condvar: Condvar,
    /// Pseudo thread ID for GetCurrentThreadId / OwningThread in CRITICAL_SECTION.
    pub thread_id: u32,
}

impl ThreadObject {
    /// Create a new thread object (initially running).
    pub fn new(thread_id: u32) -> Self {
        Self {
            exit_status: Mutex::new(None),
            condvar: Condvar::new(),
            thread_id,
        }
    }

    /// Mark the thread as exited with the given exit code.
    pub fn set_exited(&self, code: i32) {
        *self.exit_status.lock().unwrap() = Some(code);
        self.condvar.notify_all();
    }

    /// Returns true if the thread has exited.
    pub fn has_exited(&self) -> bool {
        self.exit_status.lock().unwrap().is_some()
    }
}

/// Internal state for an NT semaphore object.
#[derive(Debug)]
pub struct SemaphoreObject {
    /// Mutex-protected current count.
    pub state: Mutex<i32>,
    /// Condvar for waiters to block on.
    pub condvar: Condvar,
    /// Maximum count.
    pub max_count: i32,
}

impl SemaphoreObject {
    /// Create a new semaphore.
    pub fn new(initial_count: i32, max_count: i32) -> Self {
        Self {
            state: Mutex::new(initial_count),
            condvar: Condvar::new(),
            max_count,
        }
    }
}

/// Internal state for an NT keyed event object.
///
/// Keyed events are a low-level futex-like primitive used internally by
/// SRW locks and condition variables. Each wait/release pair is matched 1:1:
/// one NtReleaseKeyedEvent wakes exactly one NtWaitForKeyedEvent on the same
/// key, and vice versa.
#[derive(Debug)]
pub struct KeyedEventObject {
    /// Per-key queue state with per-caller release tokens for 1:1 matching.
    pub state: Mutex<BTreeMap<usize, KeyedWaiterQueue>>,
    /// Condvar shared by all waiters/releasers on this keyed event object.
    pub condvar: Condvar,
    /// Monotonic counter for unique release token IDs.
    next_release_id: Mutex<u64>,
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
            condvar: Condvar::new(),
            next_release_id: Mutex::new(0),
        }
    }

    /// Allocate a unique release token ID.
    pub fn alloc_release_id(&self) -> u64 {
        let mut id = self.next_release_id.lock().unwrap();
        let val = *id;
        *id = val.wrapping_add(1);
        val
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
#[derive(Debug)]
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

    /// Look up an object by handle (mutable).
    pub fn get_mut(&mut self, handle: u32) -> Option<&mut NtObject> {
        self.objects.get_mut(&handle)
    }

    /// Close a handle, returning the object if it existed.
    ///
    /// For File objects with host handles, the caller is responsible for
    /// closing the host handle (via `close_host_handle`).
    pub fn close(&mut self, handle: u32) -> Option<NtObject> {
        let obj = self.objects.remove(&handle);
        // If this is a File with a host handle, close it.
        if let Some(NtObject::File { host_handle, .. }) = &obj {
            if *host_handle != 0 && *host_handle != usize::MAX {
                close_host_handle(*host_handle);
            }
        }
        obj
    }

    /// Returns true if the handle exists in the table.
    pub fn contains(&self, handle: u32) -> bool {
        self.objects.contains_key(&handle)
    }

    /// Duplicate a handle, creating a new handle table entry pointing to
    /// the same underlying object. For File objects, a new host handle is
    /// obtained via DuplicateHandle and the position `Arc` is cloned so both
    /// handles share the same file pointer state. Returns the new handle,
    /// or `None` if the source handle doesn't exist or duplication fails.
    pub fn duplicate(&mut self, source: u32) -> Option<u32> {
        let obj = self.objects.get(&source)?;
        let new_obj = match obj {
            NtObject::ConsoleInput => NtObject::ConsoleInput,
            NtObject::ConsoleOutput { is_stderr } => NtObject::ConsoleOutput {
                is_stderr: *is_stderr,
            },
            NtObject::File {
                path,
                host_handle,
                position,
            } => {
                let new_host = duplicate_host_handle(*host_handle);
                if new_host == 0 || new_host == usize::MAX {
                    return None;
                }
                NtObject::File {
                    path: path.clone(),
                    host_handle: new_host,
                    position: Arc::clone(position),
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
            NtObject::KeyedEvent(k) => NtObject::KeyedEvent(Arc::clone(k)),
            NtObject::Thread(t) => NtObject::Thread(Arc::clone(t)),
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

/// Close a Windows host file handle.
#[cfg(target_os = "windows")]
fn close_host_handle(handle: usize) {
    unsafe extern "system" {
        fn CloseHandle(handle: usize) -> i32;
    }
    unsafe {
        CloseHandle(handle);
    }
}

#[cfg(not(target_os = "windows"))]
fn close_host_handle(_handle: usize) {}

/// Duplicate a Windows host file handle via DuplicateHandle.
#[cfg(target_os = "windows")]
fn duplicate_host_handle(handle: usize) -> usize {
    unsafe extern "system" {
        fn GetCurrentProcess() -> usize;
        fn DuplicateHandle(
            source_process: usize,
            source_handle: usize,
            target_process: usize,
            target_handle: *mut usize,
            desired_access: u32,
            inherit: i32,
            options: u32,
        ) -> i32;
    }

    let mut new_handle: usize = 0;
    let current = unsafe { GetCurrentProcess() };
    // DUPLICATE_SAME_ACCESS = 0x2
    let ok = unsafe { DuplicateHandle(current, handle, current, &raw mut new_handle, 0, 0, 0x2) };
    if ok != 0 { new_handle } else { 0 }
}

#[cfg(not(target_os = "windows"))]
fn duplicate_host_handle(_handle: usize) -> usize {
    0
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
