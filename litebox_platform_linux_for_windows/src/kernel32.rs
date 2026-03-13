// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! KERNEL32.dll function implementations
//!
//! This module provides Linux-based implementations of KERNEL32 functions
//! that are commonly used by Windows programs. These are higher-level wrappers
//! around NTDLL functions.

// Allow unsafe operations inside unsafe functions since the entire function is unsafe
#![allow(unsafe_op_in_unsafe_fn)]
// Allow cast warnings as we're implementing Windows API which requires specific integer types
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
// Allow raw-pointer alignment casts: we always use write_unaligned / read_unaligned
// when writing to potentially unaligned addresses derived from *mut u8 buffers.
#![allow(clippy::cast_ptr_alignment)]

use std::alloc;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

// Code page constants for MultiByteToWideChar and WideCharToMultiByte
const CP_ACP: u32 = 0;
const CP_UTF8: u32 = 65001;

// Heap constants for HeapAlloc
const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

// Epoch difference between Windows (1601-01-01) and Unix (1970-01-01) in seconds
const EPOCH_DIFF: i64 = 11_644_473_600;

/// Thread Local Storage (TLS) manager
///
/// Windows TLS allows each thread to store thread-specific data.
/// This is implemented using a global HashMap where the key is
/// (thread_id, slot_index) and the value is the stored pointer.
struct TlsManager {
    /// Next available TLS slot index
    next_slot: u32,
    /// Map of (thread_id, slot_index) -> value
    storage: HashMap<(u32, u32), usize>,
}

impl TlsManager {
    fn new() -> Self {
        Self {
            next_slot: 0,
            storage: HashMap::new(),
        }
    }

    fn alloc_slot(&mut self) -> Option<u32> {
        // Windows TLS has a limited number of slots (64 or 1088 depending on version)
        // We'll use a generous limit
        const MAX_TLS_SLOTS: u32 = 1088;
        if self.next_slot >= MAX_TLS_SLOTS {
            return None;
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        Some(slot)
    }

    fn free_slot(&mut self, slot: u32, thread_id: u32) -> bool {
        // Remove the value for this thread and slot
        self.storage.remove(&(thread_id, slot));
        true
    }

    fn get_value(&self, slot: u32, thread_id: u32) -> usize {
        self.storage.get(&(thread_id, slot)).copied().unwrap_or(0)
    }

    fn set_value(&mut self, slot: u32, thread_id: u32, value: usize) -> bool {
        self.storage.insert((thread_id, slot), value);
        true
    }
}

/// Global TLS manager protected by a mutex
static TLS_MANAGER: Mutex<Option<TlsManager>> = Mutex::new(None);

/// Initialize the TLS manager (called once)
fn ensure_tls_manager_initialized() {
    let mut manager = TLS_MANAGER.lock().unwrap();
    if manager.is_none() {
        *manager = Some(TlsManager::new());
    }
}

/// Heap allocation tracker
///
/// Tracks allocation sizes for HeapAlloc so that HeapFree and HeapReAlloc
/// can properly deallocate memory using the correct Layout.
struct HeapAllocationTracker {
    /// Map of pointer address -> (size, alignment)
    allocations: HashMap<usize, (usize, usize)>,
}

impl HeapAllocationTracker {
    fn new() -> Self {
        Self {
            allocations: HashMap::new(),
        }
    }

    fn track_allocation(&mut self, ptr: *mut u8, size: usize, align: usize) {
        if !ptr.is_null() {
            self.allocations.insert(ptr as usize, (size, align));
        }
    }

    fn get_allocation(&self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.get(&(ptr as usize)).copied()
    }

    fn remove_allocation(&mut self, ptr: *mut core::ffi::c_void) -> Option<(usize, usize)> {
        self.allocations.remove(&(ptr as usize))
    }
}

/// Global heap allocation tracker protected by a mutex
static HEAP_TRACKER: Mutex<Option<HeapAllocationTracker>> = Mutex::new(None);

/// Initialize the heap tracker (called once)
fn ensure_heap_tracker_initialized() {
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if tracker.is_none() {
        *tracker = Some(HeapAllocationTracker::new());
    }
}

// ── File-handle registry ──────────────────────────────────────────────────
// Maps Win32 HANDLE values (encoded as usize) to open `File` objects.

static FILE_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x1_0000);

struct FileEntry {
    file: File,
    /// If non-zero, this file is associated with an IOCP (handle value stored here).
    iocp_handle: usize,
    /// Completion key supplied when associating this file with an IOCP.
    completion_key: usize,
}

impl FileEntry {
    fn new(file: File) -> Self {
        Self {
            file,
            iocp_handle: 0,
            completion_key: 0,
        }
    }
}

/// Global file-handle map: handle_value → FileEntry
static FILE_HANDLES: Mutex<Option<HashMap<usize, FileEntry>>> = Mutex::new(None);

fn with_file_handles<R>(f: impl FnOnce(&mut HashMap<usize, FileEntry>) -> R) -> R {
    let mut guard = FILE_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Windows error code returned when no more handles can be opened.
const ERROR_TOO_MANY_OPEN_FILES: u32 = 4;

/// Maximum number of concurrently open file handles.
/// `CreateFileW` returns `ERROR_TOO_MANY_OPEN_FILES` (4) once this limit is
/// reached.  1024 matches a common Windows per-process soft limit.
#[cfg(not(test))]
const MAX_OPEN_FILE_HANDLES: usize = 1024;
/// Use a smaller limit in tests to avoid exhausting the process fd table and
/// to keep the test fast.
#[cfg(test)]
const MAX_OPEN_FILE_HANDLES: usize = 8;

/// Allocate a new Win32-style file handle value (non-null, not INVALID_HANDLE_VALUE).
fn alloc_file_handle() -> usize {
    FILE_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Directory-search-handle registry ─────────────────────────────────────
// Maps synthetic HANDLE values (usize) to in-progress directory searches.
// Used by FindFirstFileW / FindNextFileW / FindClose.
//
// Note: entries are only removed by FindClose. A Windows program that exits
// without calling FindClose (or crashes) will leave entries in this map for
// the lifetime of the process, holding onto Vec allocations. This is
// consistent with the FILE_HANDLES registry and is acceptable for a
// sandboxed single-process environment.

static FIND_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x2_0000);

struct DirSearchState {
    entries: Vec<std::fs::DirEntry>,
    current_index: usize,
    pattern: String,
}

static FIND_HANDLES: Mutex<Option<HashMap<usize, DirSearchState>>> = Mutex::new(None);

fn with_find_handles<R>(f: impl FnOnce(&mut HashMap<usize, DirSearchState>) -> R) -> R {
    let mut guard = FIND_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

/// Maximum number of concurrently open directory-search handles.
#[cfg(not(test))]
const MAX_OPEN_FIND_HANDLES: usize = 1024;
/// Smaller limit during tests.
#[cfg(test)]
const MAX_OPEN_FIND_HANDLES: usize = 8;

fn alloc_find_handle() -> usize {
    FIND_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Thread-handle registry ────────────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to spawned Rust thread state.
// Used by CreateThread / WaitForSingleObject / WaitForMultipleObjects.

static THREAD_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x3_0000);

struct ThreadEntry {
    join_handle: Option<thread::JoinHandle<u32>>,
    exit_code: Arc<Mutex<Option<u32>>>,
}

/// Global thread-handle map: handle_value → ThreadEntry
static THREAD_HANDLES: Mutex<Option<HashMap<usize, ThreadEntry>>> = Mutex::new(None);

fn with_thread_handles<R>(f: impl FnOnce(&mut HashMap<usize, ThreadEntry>) -> R) -> R {
    let mut guard = THREAD_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_thread_handle() -> usize {
    THREAD_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Event-handle registry ─────────────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to Condvar-backed event objects.
// Used by CreateEventW / SetEvent / ResetEvent / WaitForSingleObject.

static EVENT_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x4_0000);

struct EventEntry {
    manual_reset: bool,
    state: Arc<(Mutex<bool>, Condvar)>,
}

static EVENT_HANDLES: Mutex<Option<HashMap<usize, EventEntry>>> = Mutex::new(None);

fn with_event_handles<R>(f: impl FnOnce(&mut HashMap<usize, EventEntry>) -> R) -> R {
    let mut guard = EVENT_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_event_handle() -> usize {
    EVENT_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── File-mapping-handle registry ──────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to file-mapping metadata.
// Used by CreateFileMappingA, MapViewOfFile, UnmapViewOfFile.

static FILE_MAPPING_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x6_0000);

struct FileMappingEntry {
    /// Raw file descriptor; -1 for anonymous (pagefile-backed) mappings.
    raw_fd: i32,
    /// Total mapping size in bytes (0 = use full file).
    size: u64,
    /// Windows PAGE_* protection flags from CreateFileMappingA.
    protect: u32,
}

static FILE_MAPPING_HANDLES: Mutex<Option<HashMap<usize, FileMappingEntry>>> = Mutex::new(None);

fn with_file_mapping_handles<R>(f: impl FnOnce(&mut HashMap<usize, FileMappingEntry>) -> R) -> R {
    let mut guard = FILE_MAPPING_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_file_mapping_handle() -> usize {
    FILE_MAPPING_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── Sync-object handle registry (mutexes + semaphores) ─────────────────────
static SYNC_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x7_0000);

type MutexStateArc = Arc<(Mutex<Option<(u32, u32)>>, Condvar)>;

enum SyncObjectEntry {
    Mutex {
        name: Option<String>,
        state: MutexStateArc,
    },
    Semaphore {
        name: Option<String>,
        max_count: i32,
        state: Arc<(Mutex<i32>, Condvar)>,
    },
}

static SYNC_HANDLES: Mutex<Option<HashMap<usize, SyncObjectEntry>>> = Mutex::new(None);

fn with_sync_handles<R>(f: impl FnOnce(&mut HashMap<usize, SyncObjectEntry>) -> R) -> R {
    let mut guard = SYNC_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_sync_handle() -> usize {
    SYNC_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── IOCP (I/O Completion Port) handle registry ────────────────────────────
// Maps synthetic HANDLE values (usize) to I/O completion port state.
// Used by CreateIoCompletionPort, GetQueuedCompletionStatus, and
// PostQueuedCompletionStatus.

static IOCP_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x8_0000);

/// A single completion packet dequeued from an I/O completion port.
struct IocpCompletionPacket {
    /// Number of bytes transferred by the I/O operation.
    bytes_transferred: u32,
    /// Per-file completion key supplied to `CreateIoCompletionPort`.
    completion_key: usize,
    /// OVERLAPPED pointer associated with the operation (as raw address).
    overlapped: usize,
    /// Windows error code for the operation (0 = success).
    error_code: u32,
}

/// Shared IOCP queue state (referenced by Arc so it can be cloned across
/// file-handle entries that are associated with the same port).
struct IocpSharedState {
    queue: VecDeque<IocpCompletionPacket>,
}

struct IocpEntry {
    state: Arc<(Mutex<IocpSharedState>, Condvar)>,
}

static IOCP_HANDLES: Mutex<Option<HashMap<usize, IocpEntry>>> = Mutex::new(None);

fn with_iocp_handles<R>(f: impl FnOnce(&mut HashMap<usize, IocpEntry>) -> R) -> R {
    let mut guard = IOCP_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_iocp_handle() -> usize {
    IOCP_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

/// Post a completion packet to an IOCP identified by its handle value.
/// Returns `true` if the port was found and the packet was enqueued.
fn post_iocp_completion(
    iocp_handle: usize,
    bytes_transferred: u32,
    completion_key: usize,
    overlapped: usize,
    error_code: u32,
) -> bool {
    with_iocp_handles(|map| {
        let Some(entry) = map.get(&iocp_handle) else {
            return false;
        };
        let (lock, cvar) = entry.state.as_ref();
        let mut state = lock.lock().unwrap();
        state.queue.push_back(IocpCompletionPacket {
            bytes_transferred,
            completion_key,
            overlapped,
            error_code,
        });
        cvar.notify_one();
        true
    })
}

// ── Process-handle registry ───────────────────────────────────────────────
// Maps synthetic HANDLE values (usize) to spawned child-process state.
// Used by CreateProcessW / WaitForSingleObject / GetExitCodeProcess /
// TerminateProcess / CloseHandle.

static PROCESS_HANDLE_COUNTER: AtomicUsize = AtomicUsize::new(0x9_0000);

struct ProcessEntry {
    /// The spawned child; `None` once `wait()` has been called.
    child: Arc<Mutex<Option<std::process::Child>>>,
    /// The real OS process ID.
    pid: u32,
    /// Cached exit code; `None` while the process is still running.
    exit_code: Arc<Mutex<Option<u32>>>,
    /// `true` for the hProcess handle; `false` for the hThread placeholder.
    is_process: bool,
}

static PROCESS_HANDLES: Mutex<Option<HashMap<usize, ProcessEntry>>> = Mutex::new(None);

fn with_process_handles<R>(f: impl FnOnce(&mut HashMap<usize, ProcessEntry>) -> R) -> R {
    let mut guard = PROCESS_HANDLES.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn alloc_process_handle() -> usize {
    PROCESS_HANDLE_COUNTER.fetch_add(4, Ordering::SeqCst)
}

// ── APC (Asynchronous Procedure Call) queue ────────────────────────────────
// Each thread has its own APC queue.  ReadFileEx / WriteFileEx enqueue an APC
// on the calling thread; SleepEx / WaitForSingleObjectEx with alertable=TRUE
// drain the queue by invoking each callback.
//
// LPOVERLAPPED_COMPLETION_ROUTINE:
//   VOID WINAPI CompletionRoutine(DWORD errCode, DWORD bytesTransferred, LPOVERLAPPED);

type OverlappedCompletionRoutine = unsafe extern "win64" fn(u32, u32, *mut core::ffi::c_void);

struct ApcEntry {
    error_code: u32,
    bytes_transferred: u32,
    /// Stored as a raw address so it can live in a thread_local without
    /// requiring the pointer itself to be `Send`.
    overlapped: usize,
    callback: OverlappedCompletionRoutine,
}

thread_local! {
    static APC_QUEUE: RefCell<Vec<ApcEntry>> = const { RefCell::new(Vec::new()) };
}

/// Drain all pending APCs for the current thread.
/// Returns `true` if at least one APC was executed.
/// # Safety
/// Calls Windows-ABI function pointers; the caller must ensure that the
/// stored callbacks and OVERLAPPED pointers remain valid.
unsafe fn drain_apc_queue() -> bool {
    let entries: Vec<ApcEntry> = APC_QUEUE.with(|q| std::mem::take(&mut *q.borrow_mut()));
    if entries.is_empty() {
        return false;
    }
    for entry in entries {
        let overlapped = entry.overlapped as *mut core::ffi::c_void;
        (entry.callback)(entry.error_code, entry.bytes_transferred, overlapped);
    }
    true
}

// ── OVERLAPPED structure layout (Windows x64) ─────────────────────────────
// offset  0 : Internal      (u64) – NTSTATUS / error code
// offset  8 : InternalHigh  (u64) – bytes transferred
// offset 16 : Offset        (u32) – file-offset low  (union with Pointer)
// offset 20 : OffsetHigh    (u32) – file-offset high
// offset 24 : hEvent        (*mut c_void)
//
// We only read/write Internal and InternalHigh.

const OVERLAPPED_INTERNAL_OFFSET: usize = 0;
const OVERLAPPED_INTERNAL_HIGH_OFFSET: usize = 8;

/// Write the result fields of an OVERLAPPED structure.
/// `status` is 0 (STATUS_SUCCESS) on success.
/// # Safety
/// `overlapped` must point to a writable Windows OVERLAPPED structure.
unsafe fn set_overlapped_result(overlapped: *mut core::ffi::c_void, status: u64, bytes: u64) {
    if overlapped.is_null() {
        return;
    }
    let base = overlapped.cast::<u8>();
    core::ptr::write_unaligned(base.add(OVERLAPPED_INTERNAL_OFFSET).cast::<u64>(), status);
    core::ptr::write_unaligned(
        base.add(OVERLAPPED_INTERNAL_HIGH_OFFSET).cast::<u64>(),
        bytes,
    );
}

/// Read the result fields of an OVERLAPPED structure.
/// Returns `(status, bytes_transferred)`.
/// # Safety
/// `overlapped` must point to a readable Windows OVERLAPPED structure.
unsafe fn get_overlapped_result(overlapped: *const core::ffi::c_void) -> (u64, u64) {
    if overlapped.is_null() {
        return (u64::MAX, 0);
    }
    let base = overlapped.cast::<u8>();
    let status = core::ptr::read_unaligned(base.add(OVERLAPPED_INTERNAL_OFFSET).cast::<u64>());
    let bytes = core::ptr::read_unaligned(base.add(OVERLAPPED_INTERNAL_HIGH_OFFSET).cast::<u64>());
    (status, bytes)
}

// ── Console title ─────────────────────────────────────────────────────────
static CONSOLE_TITLE: Mutex<Option<String>> = Mutex::new(None);

// ── Mapped-view registry ───────────────────────────────────────────────────
// Maps base_address (usize) → mapping size (usize) so UnmapViewOfFile can
// call munmap with the correct length.

static MAPPED_VIEWS: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);

fn with_mapped_views<R>(f: impl FnOnce(&mut HashMap<usize, usize>) -> R) -> R {
    let mut guard = MAPPED_VIEWS.lock().unwrap();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

// ── DLL-load-handle registry ──────────────────────────────────────────────
// Maps synthetic HMODULE values (usize) to loaded-DLL information.
// Used by LoadLibraryA/W, GetModuleHandleA/W, GetProcAddress, and FreeLibrary.

/// A single entry in the DLL-load registry.
struct DllLoadEntry {
    /// Canonical DLL name (mixed-case, as supplied at registration time).
    #[allow(dead_code)]
    name: String,
    /// Exported function name → trampoline address.
    exports: HashMap<String, usize>,
}

/// Registry state protected by `DLL_HANDLES`.
struct DllLoadRegistry {
    /// Next handle value to assign.  Starts at 0x5_0000, increments by 4.
    next_handle: usize,
    /// Normalised (upper-case) DLL name → synthetic HMODULE.
    by_name: HashMap<String, usize>,
    /// Synthetic HMODULE → `DllLoadEntry`.
    by_handle: HashMap<usize, DllLoadEntry>,
}

impl DllLoadRegistry {
    fn new() -> Self {
        Self {
            // Start at 0x5_0000 to stay consistent with other handle-counter ranges:
            // FILE_HANDLE_COUNTER = 0x1_0000, FIND = 0x2_0000, THREAD = 0x3_0000, EVENT = 0x4_0000.
            next_handle: 0x5_0000,
            by_name: HashMap::new(),
            by_handle: HashMap::new(),
        }
    }

    /// Returns the existing handle for `dll_name` (case-insensitive), or
    /// allocates a new one and creates an empty entry.
    fn get_or_create_handle(&mut self, dll_name: &str) -> usize {
        let upper = dll_name.to_uppercase();
        if let Some(&h) = self.by_name.get(&upper) {
            return h;
        }
        let h = self.next_handle;
        // Increment by 4 to match the alignment convention used by the other
        // synthetic-handle ranges in this module.
        self.next_handle += 4;
        self.by_name.insert(upper, h);
        self.by_handle.insert(
            h,
            DllLoadEntry {
                name: dll_name.to_string(),
                exports: HashMap::new(),
            },
        );
        h
    }
}

/// Global DLL-handle registry: HMODULE handle → `DllLoadEntry`.
static DLL_HANDLES: Mutex<Option<DllLoadRegistry>> = Mutex::new(None);

fn with_dll_handles<R>(f: impl FnOnce(&mut DllLoadRegistry) -> R) -> R {
    let mut guard = DLL_HANDLES.lock().unwrap();
    let reg = guard.get_or_insert_with(DllLoadRegistry::new);
    f(reg)
}

/// Register Windows DLL function addresses for use by `LoadLibraryA/W` and `GetProcAddress`.
///
/// Each entry is `(dll_name, function_name, function_address)` where
/// `function_address` is the trampoline address that handles Windows x64 → System V AMD64 ABI
/// translation.  Called by the runner after trampolines have been initialised.
pub fn register_dynamic_exports(exports: &[(String, String, usize)]) {
    with_dll_handles(|reg| {
        for (dll_name, func_name, addr) in exports {
            let h = reg.get_or_create_handle(dll_name);
            if let Some(entry) = reg.by_handle.get_mut(&h) {
                entry.exports.insert(func_name.clone(), *addr);
            }
        }
    });
}

/// Windows thread start function pointer type (MS-x64 ABI).
/// LPTHREAD_START_ROUTINE = DWORD (WINAPI *)(LPVOID lpThreadParameter)
type WindowsThreadStart = unsafe extern "win64" fn(*mut core::ffi::c_void) -> u32;

/// Extract the DLL basename from a Windows-style or POSIX path.
///
/// `std::path::Path::file_name()` only understands the *host* OS separator.
/// On Linux that means `C:\Windows\System32\kernel32.dll` is treated as a
/// single component, so the lookup would fail for any caller that passes a
/// full Windows path.  This function handles both `\\` and `/` separators and
/// also strips a trailing separator, giving consistent results regardless of
/// whether the caller supplies a bare name or a full path.
fn dll_basename(path: &str) -> &str {
    // Trim trailing separators first (e.g. "dir\\" → "dir")
    let trimmed = path.trim_end_matches(['\\', '/']);
    // Then split on both Windows and POSIX separators and take the last component.
    trimmed
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(trimmed)
}

/// Simple glob pattern matching (Windows-style: `*` = any substring, `?` = any char).
/// Comparison is case-insensitive (ASCII).
fn find_matches_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern == "*.*" {
        return true;
    }
    let name_lower: String = name.to_ascii_lowercase();
    let pat_lower: String = pattern.to_ascii_lowercase();
    glob_match(name_lower.as_bytes(), pat_lower.as_bytes())
}

fn glob_match(name: &[u8], pattern: &[u8]) -> bool {
    let mut i: usize = 0; // index into name
    let mut j: usize = 0; // index into pattern

    // Last position of '*' in pattern, and the index in name that matched it.
    let mut star_idx: Option<usize> = None;
    let mut match_idx: usize = 0;

    while i < name.len() {
        if j < pattern.len() && (pattern[j] == b'?' || pattern[j] == name[i]) {
            // Current characters match (or pattern has '?'): advance both.
            i += 1;
            j += 1;
        } else if j < pattern.len() && pattern[j] == b'*' {
            // Record position of '*' and the corresponding match index in name.
            star_idx = Some(j);
            match_idx = i;
            j += 1;
        } else if let Some(si) = star_idx {
            // Mismatch, but we have a previous '*': backtrack.
            j = si + 1;
            match_idx += 1;
            if match_idx > name.len() {
                return false;
            }
            i = match_idx;
        } else {
            // Mismatch and no '*' to fall back to.
            return false;
        }
    }

    // Consume any trailing '*' in the pattern: they can match an empty suffix.
    while j < pattern.len() && pattern[j] == b'*' {
        j += 1;
    }

    j == pattern.len()
}

/// Fill a raw `WIN32_FIND_DATAW` buffer from a directory entry.
///
/// The caller-supplied `find_data` must point to at least 592 bytes (the size of
/// `WIN32_FIND_DATAW`).  The layout written matches the Windows ABI exactly:
///   - offset   0: dwFileAttributes (u32)
///   - offset   4: ftCreationTime   (2×u32, low first)
///   - offset  12: ftLastAccessTime (2×u32)
///   - offset  20: ftLastWriteTime  (2×u32)
///   - offset  28: nFileSizeHigh (u32)
///   - offset  32: nFileSizeLow  (u32)
///   - offset  36: dwReserved0   (u32)
///   - offset  40: dwReserved1   (u32)
///   - offset  44: cFileName\[260\] (u16 array)
///   - offset 564: cAlternateFileName\[14\] (u16 array)
///
/// # Safety
/// `find_data` must point to a writable buffer of at least 592 bytes.
unsafe fn fill_find_data(entry: &std::fs::DirEntry, find_data: *mut u8) {
    const WIN32_FIND_DATAW_SIZE: usize = 592;
    if find_data.is_null() {
        return;
    }
    // Always zero-initialize the buffer so that callers never observe
    // uninitialized memory, even if metadata retrieval fails.
    // SAFETY: Caller guarantees `find_data` points to at least
    // `WIN32_FIND_DATAW_SIZE` writable bytes (see function safety contract),
    // and we've just checked that the pointer is non-null.
    std::ptr::write_bytes(find_data, 0u8, WIN32_FIND_DATAW_SIZE);

    let Ok(metadata) = entry.metadata() else {
        // Return with a zeroed structure on metadata failure.
        return;
    };
    fill_find_data_from_path(&entry.path(), &metadata, find_data);
}

/// Parse a Windows/Linux path into (directory_string, pattern_string).
/// e.g. "/tmp/foo/*.txt" → ("/tmp/foo", "*.txt")
///      "/tmp/foo/bar.txt" → ("/tmp/foo", "bar.txt")
fn split_dir_and_pattern(linux_path: &str) -> (String, String) {
    let path = std::path::Path::new(linux_path);
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let dir = if parent.as_os_str().is_empty() {
            ".".to_string()
        } else {
            parent.to_string_lossy().into_owned()
        };
        (dir, name.to_string_lossy().into_owned())
    } else {
        (".".to_string(), linux_path.to_string())
    }
}

/// Write `data` to the file registered under `handle` in the kernel32 file-handle map.
///
/// Returns `Some(bytes_written)` if the handle was found, `None` otherwise.
/// Used by `ntdll_impl.rs` to route `NtWriteFile` calls through the kernel32 handle registry.
pub fn nt_write_file_handle(handle: u64, data: &[u8]) -> Option<usize> {
    let handle_val = handle as usize;
    with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.write(data).ok()
        } else {
            None
        }
    })
}

/// Read from the file registered under `handle` in the kernel32 file-handle map.
///
/// Returns `Some(bytes_read)` if the handle was found, `None` otherwise.
/// Used by `ntdll_impl.rs` to route `NtReadFile` calls through the kernel32 handle registry.
pub fn nt_read_file_handle(handle: u64, buf: &mut [u8]) -> Option<usize> {
    let handle_val = handle as usize;
    with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.read(buf).ok()
        } else {
            None
        }
    })
}

/// Return the command line as a UTF-8 `String`.
///
/// Reads `PROCESS_COMMAND_LINE` (UTF-16) and converts to UTF-8.  Returns an empty
/// string if the command line has not been set yet.
pub fn get_command_line_utf8() -> String {
    PROCESS_COMMAND_LINE
        .get()
        .map(|v| {
            // strip trailing null terminator(s) before converting
            let end = v.iter().position(|&c| c == 0).unwrap_or(v.len());
            String::from_utf16_lossy(&v[..end])
        })
        .unwrap_or_default()
}

// ── Environment-strings block registry ───────────────────────────────────
// Each call to `GetEnvironmentStringsW` allocates a block.  The block's
// raw pointer is recorded here so that `FreeEnvironmentStringsW` can
// reconstruct the `Box` and drop it, preventing unbounded memory growth.

/// Newtype wrapper so that `*mut u16` (which is not `Send`) can be stored in a
/// `static Mutex`.  Safety: the pointer is only ever accessed while holding the
/// mutex lock, so no data race can occur.
struct SendablePtr(*mut u16);
// SAFETY: We only ever access the pointer while holding the mutex, so it is
// effectively single-threaded at any given moment.
unsafe impl Send for SendablePtr {}

static ENV_STRINGS_BLOCKS: Mutex<Option<Vec<SendablePtr>>> = Mutex::new(None);

/// Process command line (UTF-16, null-terminated) set by the runner before entry point execution
static PROCESS_COMMAND_LINE: OnceLock<Vec<u16>> = OnceLock::new();

/// Optional sandbox root directory. When set, all file paths resolved by
/// `wide_path_to_linux` are restricted to this prefix. Paths that escape the
/// sandbox (e.g. via `..` traversal) are replaced with an empty string so that
/// the subsequent file operation fails safely.
static SANDBOX_ROOT: Mutex<Option<String>> = Mutex::new(None);

/// Volume serial number reported by `GetFileInformationByHandle`.
///
/// `0` means "not yet set"; the first call to `get_volume_serial()` will
/// generate a value from the process ID and the current time and store it
/// here so that subsequent calls return the same value for the lifetime of
/// the process.  The runner may call `set_volume_serial` before the entry
/// point executes to pin a specific value instead.
static VOLUME_SERIAL: AtomicU32 = AtomicU32::new(0);

/// Override the volume serial number returned by `GetFileInformationByHandle`.
///
/// Call this before executing the PE entry point.  Passing `0` clears any
/// previously pinned value, causing the next `GetFileInformationByHandle`
/// call to generate a fresh per-run value.
pub fn set_volume_serial(serial: u32) {
    VOLUME_SERIAL.store(serial, Ordering::Relaxed);
}

/// Return the volume serial number, generating one lazily if none has been set.
///
/// The generated value is derived from the process ID and the current
/// system time, giving a different value on each run without requiring an
/// external RNG dependency.
fn get_volume_serial() -> u32 {
    let current = VOLUME_SERIAL.load(Ordering::Relaxed);
    if current != 0 {
        return current;
    }
    // Generate: mix process ID with sub-second time to get a per-run value.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // Simple multiplicative hash so even similar inputs differ widely.
    let generated = pid.wrapping_mul(2_654_435_761).wrapping_add(nanos) | 1; // ensure non-zero
    // Only store the generated value if nobody else stored one concurrently.
    match VOLUME_SERIAL.compare_exchange(0, generated, Ordering::Relaxed, Ordering::Relaxed) {
        Ok(_) => generated,
        Err(stored) => stored, // another thread beat us; use their value
    }
}

/// Set the process command line from runner-provided arguments.
///
/// Call this before executing the entry point to ensure Windows programs receive
/// the correct command line via `GetCommandLineW` and `__getmainargs`.
/// The first element of `args` should be the program name/path.
pub fn set_process_command_line(args: &[String]) {
    let cmd_line = args
        .iter()
        .map(|arg| {
            if arg.contains(' ') || arg.contains('"') {
                // Windows command-line quoting: escape backslashes before a quote,
                // escape any embedded quotes with backslash, then wrap in double quotes.
                format!("\"{}\"", arg.replace('\\', "\\\\").replace('"', "\\\""))
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let mut utf16: Vec<u16> = cmd_line.encode_utf16().collect();
    utf16.push(0);
    // Ignore errors if already set (idempotent in tests)
    let _ = PROCESS_COMMAND_LINE.set(utf16);
}

/// Restrict all file-path operations to the given directory root.
///
/// When a sandbox root is configured, `wide_path_to_linux` will normalise
/// every path (resolving all `..` and `.` components) and verify that the
/// result still starts with `root`.  Paths that escape the sandbox are
/// replaced with an empty string so that the corresponding file operation
/// fails with `ERROR_ACCESS_DENIED` (or similar) rather than accessing an
/// unexpected location.
///
/// May be called multiple times to change or clear the sandbox root
/// (`None` disables sandboxing).
///
/// # Panics
/// Panics if the internal sandbox-root mutex is poisoned.
pub fn set_sandbox_root(root: &str) {
    *SANDBOX_ROOT.lock().unwrap() = Some(root.to_owned());
}

/// Apply the sandbox restriction to an already-translated Linux path.
///
/// If no sandbox root is configured the path is returned unchanged.
/// If a root is configured the path is normalised (all `..`/`.` resolved)
/// and returned only if it is a descendant of the root; otherwise an empty
/// string is returned so that callers treat the access as failed.
fn sandbox_guard(path: String) -> String {
    let guard = SANDBOX_ROOT.lock().unwrap();
    let Some(root) = guard.as_deref() else {
        return path;
    };
    // Normalise without hitting the filesystem (works for paths that do not
    // exist yet, e.g. a file about to be created).
    // `PathBuf::pop()` never removes the root component (`/`), so traversal
    // cannot escape below the filesystem root.
    let mut normalised = PathBuf::new();
    for component in Path::new(&path).components() {
        match component {
            Component::ParentDir => {
                normalised.pop();
            }
            Component::CurDir => {}
            _ => normalised.push(component),
        }
    }
    let normalised_str = normalised.to_string_lossy();
    if normalised_str.starts_with(root) {
        normalised_str.into_owned()
    } else {
        // Path escapes sandbox: return empty string so that the caller's file
        // operation fails with a benign error (e.g. ENOENT / ERROR_ACCESS_DENIED).
        String::new()
    }
}

/// Convert a null-terminated UTF-16 wide string pointer to a Rust `String`.
///
/// Returns an empty string if the pointer is null.
///
/// # Safety
/// Caller must ensure `wide` points to a valid null-terminated UTF-16 string.
unsafe fn wide_str_to_string(wide: *const u16) -> String {
    if wide.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: Caller guarantees `wide` is a valid null-terminated wide string.
    while *wide.add(len) != 0 {
        len += 1;
        if len > 32_768 {
            break;
        }
    }
    let slice = core::slice::from_raw_parts(wide, len);
    String::from_utf16_lossy(slice)
}

/// Convert a null-terminated UTF-16 Windows path pointer to a Linux absolute path string.
///
/// Handles the MinGW/Windows encoding where root-relative paths (e.g. `/tmp/foo`) are
/// stored with a leading NUL `u16` followed by the rest of the path without the leading
/// slash.  Backslashes are normalised to forward slashes, drive letters are stripped,
/// and the result is made absolute.
///
/// # Safety
/// Caller must ensure `wide` points to a valid null-terminated UTF-16 string.
unsafe fn wide_path_to_linux(wide: *const u16) -> String {
    if wide.is_null() {
        return String::new();
    }
    // Peek at position 0.  MinGW encodes root-relative paths (those whose
    // Windows-display form starts with '/') with u16[0] == 0x0000 followed
    // by the path body (no leading slash).
    // SAFETY: `wide` is non-null; we read one u16 to check for the pattern.
    let first = *wide;
    let path_str = if first == 0 {
        // Root-relative encoding: the path body starts at position 1.
        // SAFETY: `wide` is a valid null-terminated buffer; reading position 1 is
        // safe because position 0 is guaranteed non-terminal by the caller's contract
        // (a buffer is either empty — both u16[0] and u16[1] are 0 — or has body data).
        let second = *wide.add(1);
        if second == 0 {
            // Only the leading null — effectively an empty path body.
            String::new()
        } else {
            // We know position 1 is non-null; scan from there.
            let mut len: usize = 1;
            while len <= 32_768 {
                if *wide.add(1 + len) == 0 {
                    break;
                }
                len += 1;
            }
            let slice = core::slice::from_raw_parts(wide.add(1), len);
            String::from_utf16_lossy(slice)
        }
    } else {
        wide_str_to_string(wide)
    };

    // Normalise Windows path to Linux:
    //  - Strip optional drive letter prefix (e.g. "C:")
    //  - Replace backslashes with forward slashes
    //  - Ensure the result is absolute
    let without_drive = if path_str.len() >= 2 && path_str.as_bytes()[1] == b':' {
        &path_str[2..]
    } else {
        path_str.as_str()
    };
    let with_slashes = without_drive.replace('\\', "/");
    let absolute = if with_slashes.is_empty() || !with_slashes.starts_with('/') {
        format!("/{with_slashes}")
    } else {
        with_slashes
    };
    // Apply sandbox restriction (no-op when no sandbox root is configured).
    sandbox_guard(absolute)
}

/// Write a UTF-8 string into a caller-supplied UTF-16 buffer.
///
/// On success, returns the number of UTF-16 code units written (excluding the null
/// terminator). If `buffer` is null, `buffer_len` is 0, or `buffer_len` is smaller than
/// required, returns the required buffer size in UTF-16 code units (including the null
/// terminator). Sets `SetLastError(234)` when the buffer is smaller than required but
/// non-null.
///
/// # Safety
/// `buffer` must point to a valid writable buffer of at least `buffer_len` `u16` elements,
/// or be null.
pub(crate) unsafe fn copy_utf8_to_wide(value: &str, buffer: *mut u16, buffer_len: u32) -> u32 {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let required = utf16.len() as u32 + 1; // +1 for null terminator

    if buffer.is_null() || buffer_len == 0 {
        return required;
    }
    if buffer_len < required {
        // SAFETY: Caller guarantees buffer is non-null (checked above).
        kernel32_SetLastError(234); // ERROR_MORE_DATA
        return required;
    }
    for (i, &ch) in utf16.iter().enumerate() {
        // SAFETY: We checked buffer_len >= required, so index i is within bounds.
        *buffer.add(i) = ch;
    }
    // SAFETY: null terminator at index utf16.len(), which is < required <= buffer_len.
    *buffer.add(utf16.len()) = 0;
    utf16.len() as u32
}

/// Sleep for specified milliseconds (Sleep)
///
/// This is the Windows Sleep function that suspends execution for the specified duration.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Sleep(milliseconds: u32) {
    thread::sleep(Duration::from_millis(u64::from(milliseconds)));
}

/// Get the current thread ID (GetCurrentThreadId)
///
/// Returns the unique identifier for the current thread.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThreadId() -> u32 {
    // SAFETY: gettid is a safe syscall
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    // Truncate to u32 to match Windows API
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    (tid as u32)
}

/// Get the thread ID of a given thread handle (GetThreadId)
///
/// Returns the thread ID for the given thread handle. Since LiteBox is
/// single-threaded, any valid handle is treated as the current thread.
///
/// # Safety
/// Marked unsafe for FFI compatibility. `_thread` may be any value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetThreadId(_thread: *mut core::ffi::c_void) -> u32 {
    // Single-threaded emulation: return the current thread ID
    unsafe { kernel32_GetCurrentThreadId() }
}

/// Get the current process ID (GetCurrentProcessId)
///
/// Returns the unique identifier for the current process.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcessId() -> u32 {
    // SAFETY: getpid is a safe syscall
    let pid = unsafe { libc::getpid() };
    // Convert to u32 to match Windows API
    #[allow(clippy::cast_sign_loss)]
    (pid as u32)
}

/// Allocate a thread local storage (TLS) slot index (TlsAlloc)
///
/// Allocates a TLS index for thread-specific data. Returns TLS_OUT_OF_INDEXES (0xFFFFFFFF)
/// on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsAlloc() -> u32 {
    ensure_tls_manager_initialized();
    let mut manager = TLS_MANAGER.lock().unwrap();
    manager
        .as_mut()
        .and_then(TlsManager::alloc_slot)
        .unwrap_or(0xFFFF_FFFF) // TLS_OUT_OF_INDEXES
}

/// Free a thread local storage (TLS) slot (TlsFree)
///
/// Releases a TLS index previously allocated by TlsAlloc.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsFree(slot: u32) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.free_slot(slot, thread_id)),
    )
}

/// Get a value from thread local storage (TlsGetValue)
///
/// Retrieves the value stored in the specified TLS slot for the current thread.
/// Returns 0 if no value has been set.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for interpreting the returned pointer correctly.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsGetValue(slot: u32) -> usize {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let manager = TLS_MANAGER.lock().unwrap();
    manager.as_ref().map_or(0, |m| m.get_value(slot, thread_id))
}

/// Set a value in thread local storage (TlsSetValue)
///
/// Stores a value in the specified TLS slot for the current thread.
/// Returns non-zero on success, zero on failure.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
/// The caller is responsible for managing the lifetime of the data pointed to by `value`.
///
/// # Panics
/// Panics if the TLS_MANAGER mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TlsSetValue(slot: u32, value: usize) -> u32 {
    ensure_tls_manager_initialized();
    let thread_id = unsafe { kernel32_GetCurrentThreadId() };
    let mut manager = TLS_MANAGER.lock().unwrap();
    u32::from(
        manager
            .as_mut()
            .is_some_and(|m| m.set_value(slot, thread_id, value)),
    )
}

//
// Phase 8.2: Critical Sections
//
// Critical sections provide thread synchronization primitives for Windows programs.
// We implement them using pthread mutexes on Linux.
//

/// Windows CRITICAL_SECTION structure (opaque to us, but Windows expects ~40 bytes)
///
/// In real Windows, CRITICAL_SECTION is 40 bytes on x64 and contains:
/// - DebugInfo pointer
/// - LockCount
/// - RecursionCount
/// - OwningThread
/// - LockSemaphore
/// - SpinCount
///
/// We treat it as an opaque structure that just needs to hold a pointer to our internal data.
#[repr(C)]
pub struct CriticalSection {
    /// Internal data pointer (points to `Arc<Mutex<CriticalSectionData>>`)
    internal: usize,
    /// Padding to match Windows CRITICAL_SECTION size (40 bytes total)
    _padding: [u8; 32],
}

/// Internal data for a critical section
struct CriticalSectionData {
    /// Mutex for synchronization
    mutex: std::sync::Mutex<CriticalSectionInner>,
}

/// Inner state protected by the mutex
struct CriticalSectionInner {
    /// Current owner thread ID (0 if not owned)
    owner: u32,
    /// Recursion count (how many times the owner has entered)
    recursion: u32,
}

/// Initialize a critical section (InitializeCriticalSection)
///
/// This creates a new critical section object. The caller must provide
/// a pointer to a CRITICAL_SECTION structure (at least 40 bytes).
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` points to valid memory of at least 40 bytes
/// - The memory remains valid until `DeleteCriticalSection` is called
/// - The structure is not used concurrently during initialization
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSection(
    critical_section: *mut CriticalSection,
) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid
    let cs = unsafe { &mut *critical_section };

    // Create the internal data structure
    let data = Arc::new(CriticalSectionData {
        mutex: std::sync::Mutex::new(CriticalSectionInner {
            owner: 0,
            recursion: 0,
        }),
    });

    // Store the Arc as a raw pointer in the structure
    cs.internal = Arc::into_raw(data) as usize;
}

/// Enter a critical section (acquire the lock).
///
/// If the critical section is already owned by this thread, increments the recursion count.
/// If owned by another thread, waits until it becomes available.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized with `InitializeCriticalSection`
/// - The structure has not been deleted with `DeleteCriticalSection`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EnterCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex and check ownership
    {
        let mut inner = data.mutex.lock().unwrap();

        if inner.owner == current_thread {
            // Recursive lock - just increment the count
            inner.recursion += 1;
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
        } else {
            // Another thread owns it - this shouldn't happen with a mutex lock
            // But if it does, just wait and try again
            drop(inner);
            let mut inner2 = data.mutex.lock().unwrap();
            inner2.owner = current_thread;
            inner2.recursion = 1;
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Leave a critical section (release the lock).
///
/// Decrements the recursion count. If the count reaches zero, releases ownership.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - This thread currently owns the critical section
/// - Each `Leave` matches an `Enter`
///
/// # Panics
/// Panics if the internal mutex is poisoned (a thread panicked while holding the lock).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LeaveCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return; // Not initialized
    }

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Lock the mutex
    {
        let mut inner = data.mutex.lock().unwrap();

        // Decrement recursion count
        if inner.recursion > 0 {
            inner.recursion -= 1;
            if inner.recursion == 0 {
                // Release ownership
                inner.owner = 0;
            }
        }
        // Lock is released when inner goes out of scope
    }

    // Don't drop the Arc
    core::mem::forget(data);
}

/// Try to enter a critical section without blocking (TryEnterCriticalSection)
///
/// This attempts to acquire the critical section lock. If it's already held
/// by another thread, returns FALSE (0) immediately without blocking.
/// Returns TRUE (1) on success.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TryEnterCriticalSection(
    critical_section: *mut CriticalSection,
) -> u32 {
    if critical_section.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &*critical_section };
    if cs.internal == 0 {
        return 0; // Not initialized
    }

    // Get the current thread ID
    let current_thread = unsafe { kernel32_GetCurrentThreadId() };

    // Reconstruct the Arc (without consuming it)
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };

    // Try to lock the mutex
    let result = if let Ok(mut inner) = data.mutex.try_lock() {
        if inner.owner == current_thread {
            // Recursive lock
            inner.recursion += 1;
            1
        } else if inner.owner == 0 {
            // Take ownership
            inner.owner = current_thread;
            inner.recursion = 1;
            1
        } else {
            // Another thread owns it
            0
        }
    } else {
        // Failed to acquire mutex
        0
    };

    // Don't drop the Arc
    core::mem::forget(data);

    result
}

/// Delete a critical section (DeleteCriticalSection)
///
/// This releases all resources associated with a critical section.
/// The caller must ensure no threads are waiting on or holding the lock.
///
/// # Safety
/// The caller must ensure:
/// - `critical_section` was previously initialized
/// - No threads are currently using the critical section
/// - The critical section will not be used after this call
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteCriticalSection(critical_section: *mut CriticalSection) {
    if critical_section.is_null() {
        return;
    }

    // SAFETY: Caller guarantees the pointer is valid and initialized
    let cs = unsafe { &mut *critical_section };
    if cs.internal == 0 {
        return; // Not initialized or already deleted
    }

    // Reconstruct the Arc and let it drop to deallocate
    // SAFETY: We created this as an Arc in InitializeCriticalSection
    let _data = unsafe { Arc::from_raw(cs.internal as *const CriticalSectionData) };
    // The Arc will drop here, deallocating the data if this was the last reference

    // Clear the internal pointer
    cs.internal = 0;
}

//
// SEH (Structured Exception Handling) Infrastructure
//
// Windows x64 SEH uses three key components:
//   1. .pdata section: IMAGE_RUNTIME_FUNCTION_ENTRY records (BeginAddress, EndAddress,
//      UnwindInfoAddress) that enumerate all functions in the image.
//   2. .xdata section: UNWIND_INFO structures pointed to by each RUNTIME_FUNCTION entry,
//      describing the function's prolog in terms of UNWIND_CODE opcodes.
//   3. Runtime APIs: RtlLookupFunctionEntry, RtlVirtualUnwind, RtlUnwindEx.
//
// This implementation registers the loaded PE image's exception table and provides
// working implementations of the runtime unwind APIs.
//

/// Registered exception table for a loaded PE image
struct RegisteredExceptionTable {
    /// Base address where the image was loaded
    image_base: u64,
    /// RVA of the exception directory (.pdata section)
    pdata_rva: u32,
    /// Size of the exception directory in bytes
    pdata_size: u32,
}

static EXCEPTION_TABLE: Mutex<Option<RegisteredExceptionTable>> = Mutex::new(None);

/// Thread-local throw-site context set by `kernel32_RaiseException` and
/// consumed by `kernel32_RtlUnwindEx` to start the cleanup walk from the
/// actual throw location rather than from the catch frame.
///
/// Wine's `RtlUnwindEx` calls `RtlCaptureContext` internally to obtain the
/// current (throw-site) context; we replicate that by stashing the context
/// that `kernel32_RaiseException` already computed.
#[derive(Clone, Copy)]
struct ThrowSiteContext {
    rip: u64,
    rsp: u64,
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}
thread_local! {
    static THROW_SITE_CTX: std::cell::Cell<Option<ThrowSiteContext>>
        = const { std::cell::Cell::new(None) };
}

/// Register the exception table for a loaded PE image
///
/// This stores the location of the `.pdata` section so that
/// `RtlLookupFunctionEntry` can search it for a given program counter.
/// Must be called after the image is loaded and relocations are applied.
///
/// # Arguments
/// * `image_base` - Actual load address of the PE image
/// * `pdata_rva` - RVA of the exception directory (.pdata section)
/// * `pdata_size` - Size of the exception directory in bytes
pub fn register_exception_table(image_base: u64, pdata_rva: u32, pdata_size: u32) {
    let mut guard = EXCEPTION_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(RegisteredExceptionTable {
        image_base,
        pdata_rva,
        pdata_size,
    });
}

/// Get the image base from the registered exception table.
///
/// Returns the PE image base address, or 0 if no exception table is registered.
pub fn get_registered_image_base() -> u64 {
    let guard = EXCEPTION_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match *guard {
        Some(ref tbl) => tbl.image_base,
        None => 0,
    }
}

/// Map a program counter to the base address of its module.
///
/// Implements the Windows `RtlPcToFileHeader` API.  Returns the image base
/// of the module containing `pc`, or NULL if `pc` is not inside any known
/// module.  Also writes the base to `*base_of_image` if non-NULL.
///
/// # Safety
/// `base_of_image` must be NULL or point to writable memory for one `*mut c_void`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlPcToFileHeader(
    pc: *mut core::ffi::c_void,
    base_of_image: *mut *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // 64 MiB is a conservative upper bound for a single PE image in our
    // sandbox.  While Windows can load images up to 2 GiB, the programs
    // we target are much smaller.
    const MAX_PE_IMAGE_SIZE: u64 = 64 * 1024 * 1024;

    let pc_addr = pc as u64;
    let image_base = get_registered_image_base();
    if image_base == 0 {
        if !base_of_image.is_null() {
            unsafe { *base_of_image = core::ptr::null_mut() };
        }
        return core::ptr::null_mut();
    }
    // Check if PC falls within a reasonable range of the image.
    if pc_addr >= image_base && (pc_addr - image_base) < MAX_PE_IMAGE_SIZE {
        let base = image_base as *mut core::ffi::c_void;
        if !base_of_image.is_null() {
            unsafe { *base_of_image = base };
        }
        return base;
    }
    if !base_of_image.is_null() {
        unsafe { *base_of_image = core::ptr::null_mut() };
    }
    core::ptr::null_mut()
}

// ---- CONTEXT register byte offsets (Windows x64 CONTEXT structure) ----
// The CONTEXT structure for x64 is 1232 bytes total.
const CTX_RAX: usize = 0x78;
const CTX_RCX: usize = 0x80;
const CTX_RDX: usize = 0x88;
const CTX_RBX: usize = 0x90;
/// Offset of RSP in the Windows CONTEXT structure (x64)
pub const CTX_RSP: usize = 0x98;
const CTX_RBP: usize = 0xA0;
const CTX_RSI: usize = 0xA8;
const CTX_RDI: usize = 0xB0;
const CTX_R8: usize = 0xB8;
const CTX_R9: usize = 0xC0;
const CTX_R10: usize = 0xC8;
const CTX_R11: usize = 0xD0;
const CTX_R12: usize = 0xD8;
const CTX_R13: usize = 0xE0;
const CTX_R14: usize = 0xE8;
const CTX_R15: usize = 0xF0;
/// Offset of RIP in the Windows CONTEXT structure (x64)
pub const CTX_RIP: usize = 0xF8;
const CTX_SIZE: usize = 1232;

/// Map an x64 register number (0-15) to its byte offset in the Windows CONTEXT
fn ctx_reg_offset(reg: u8) -> usize {
    match reg {
        1 => CTX_RCX,
        2 => CTX_RDX,
        3 => CTX_RBX,
        4 => CTX_RSP,
        5 => CTX_RBP,
        6 => CTX_RSI,
        7 => CTX_RDI,
        8 => CTX_R8,
        9 => CTX_R9,
        10 => CTX_R10,
        11 => CTX_R11,
        12 => CTX_R12,
        13 => CTX_R13,
        14 => CTX_R14,
        15 => CTX_R15,
        _ => CTX_RAX, // 0 = RAX, and default for unknown
    }
}

/// Read a u64 from the Windows CONTEXT structure at the given byte offset
///
/// # Safety
/// `ctx` must point to a valid CONTEXT structure of at least CTX_SIZE bytes.
#[inline]
/// Read a u64 from a CONTEXT structure at the given offset.
///
/// # Safety
/// `ctx` must point to a valid, readable CONTEXT buffer of at least
/// `offset + 8` bytes.
pub unsafe fn ctx_read(ctx: *const u8, offset: usize) -> u64 {
    // SAFETY: Caller guarantees ctx is valid; offset is always within the 1232-byte CONTEXT.
    unsafe { ctx.add(offset).cast::<u64>().read_unaligned() }
}

/// Write a u64 into the Windows CONTEXT structure at the given byte offset
///
/// # Safety
/// `ctx` must point to a valid writable CONTEXT structure of at least CTX_SIZE bytes.
#[inline]
/// Write a u64 into a CONTEXT structure at the given offset.
///
/// # Safety
/// `ctx` must point to a valid, writable CONTEXT buffer of at least
/// `offset + 8` bytes.
pub unsafe fn ctx_write(ctx: *mut u8, offset: usize, value: u64) {
    // SAFETY: Caller guarantees ctx is valid and writable; offset is within CONTEXT bounds.
    unsafe { ctx.add(offset).cast::<u64>().write_unaligned(value) }
}

// ---- UNWIND_INFO flags ----
const UNW_FLAG_EHANDLER: u8 = 0x01;
const UNW_FLAG_UHANDLER: u8 = 0x02;
const UNW_FLAG_CHAININFO: u8 = 0x04;

// ---- GCC/MinGW SEH exception codes ----
const STATUS_GCC_THROW: u32 = 0x2047_4343;
const STATUS_GCC_UNWIND: u32 = 0x2147_4343;
const STATUS_GCC_FORCED: u32 = 0x2247_4343;

// ---- MSVC C++ exception code ----
/// MSVC C++ exception code: `0xE06D7363` == "msc" in little-endian ASCII.
/// Used by `_CxxThrowException` when calling `RaiseException`.
/// Ref: Wine `dlls/msvcrt/except_x86_64.c`, ReactOS `sdk/lib/crt/except/cppexcept.h`.
const STATUS_MSVC_CPP_EXCEPTION: u32 = 0xE06D_7363;

// ---- Exception flags (EXCEPTION_RECORD.ExceptionFlags) ----
#[allow(dead_code)]
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
const EXCEPTION_UNWINDING: u32 = 0x2;
#[allow(dead_code)]
const EXCEPTION_EXIT_UNWIND: u32 = 0x4;
#[allow(dead_code)]
const EXCEPTION_TARGET_UNWIND: u32 = 0x20;

// ---- ExceptionDisposition values returned by language handlers ----
const EXCEPTION_CONTINUE_EXECUTION: i32 = 0; // ExceptionContinueExecution
#[allow(dead_code)]
const EXCEPTION_CONTINUE_SEARCH: i32 = 1; // ExceptionContinueSearch

/// Windows x64 DISPATCHER_CONTEXT — passed to language-specific handlers
/// by `RtlVirtualUnwind` / `RtlUnwindEx`.
///
/// Total size: 96 bytes (11 fields, 8 bytes each except scope_index/fill which are 4 bytes each).
#[repr(C)]
pub(crate) struct DispatcherContext {
    pub(crate) control_pc: u64,
    pub(crate) image_base: u64,
    pub(crate) function_entry: *mut core::ffi::c_void, // PRUNTIME_FUNCTION
    pub(crate) establisher_frame: u64,
    pub(crate) target_ip: u64,
    pub(crate) context_record: *mut u8, // PCONTEXT
    pub(crate) language_handler: *mut core::ffi::c_void, // PEXCEPTION_ROUTINE
    pub(crate) handler_data: *mut core::ffi::c_void,
    pub(crate) history_table: *mut core::ffi::c_void, // PUNWIND_HISTORY_TABLE
    pub(crate) scope_index: u32,
    pub(crate) _fill0: u32,
}

/// Windows x64 EXCEPTION_RECORD (total 152 bytes for 15 ExceptionInformation entries)
#[repr(C)]
#[allow(clippy::struct_field_names)]
pub(crate) struct ExceptionRecord {
    pub(crate) exception_code: u32,
    pub(crate) exception_flags: u32,
    pub(crate) exception_record: *mut ExceptionRecord,
    pub(crate) exception_address: *mut core::ffi::c_void,
    pub(crate) number_parameters: u32,
    pub(crate) _pad: u32,
    pub(crate) exception_information: [usize; 15],
}

// ---- UNWIND_CODE opcodes ----
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

/// Apply the UNWIND_INFO for one function frame, modifying `ctx` to reflect
/// the caller's register state.
///
/// Returns the address of the language-specific exception handler (an RVA within
/// `image_base`), or `NULL` if no handler is registered for this frame.
///
/// # Safety
/// - `image_base` must be the load address of the PE image containing `unwind_info_rva`.
/// - `ctx` must point to a valid, writable Windows CONTEXT structure (≥ CTX_SIZE bytes).
/// - `control_pc` must be the program counter being unwound (used only for in-prolog detection).
/// - `begin_rva` is the function's begin RVA (used together with `control_pc`).
unsafe fn apply_unwind_info(
    image_base: u64,
    unwind_info_rva: u32,
    control_pc: u64,
    begin_rva: u32,
    ctx: *mut u8,
    handler_data_out: *mut *mut core::ffi::c_void,
    establisher_frame_out: *mut u64,
) -> *mut core::ffi::c_void {
    // SAFETY: We trust image_base + RVA to be within the loaded image.
    let ui = (image_base + u64::from(unwind_info_rva)) as *const u8;

    // UNWIND_INFO header (4 bytes):
    //   Byte 0: VersionAndFlags  = Version[2:0] | Flags[7:3]
    //   Byte 1: SizeOfProlog
    //   Byte 2: CountOfCodes
    //   Byte 3: FrameRegisterAndOffset = FrameRegister[3:0] | FrameOffset[7:4]
    let version_flags = unsafe { ui.read() };
    let version = version_flags & 0x07;
    let flags = (version_flags >> 3) & 0x1F;
    let size_of_prolog = unsafe { ui.add(1).read() } as usize;
    let count_of_codes = unsafe { ui.add(2).read() } as usize;
    let frame_reg_and_offset = unsafe { ui.add(3).read() };
    let frame_register = frame_reg_and_offset & 0x0F;
    let frame_offset = (frame_reg_and_offset >> 4) & 0x0F;

    // Only UNWIND_INFO version 1 is supported.
    if version != 1 {
        // Fallback: pop the return address and move on.
        let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
        let rip = unsafe { (rsp as *const u64).read_unaligned() };
        unsafe {
            ctx_write(ctx, CTX_RIP, rip);
            ctx_write(ctx, CTX_RSP, rsp + 8);
        }
        if !establisher_frame_out.is_null() {
            unsafe { *establisher_frame_out = rsp }
        }
        return core::ptr::null_mut();
    }

    // Determine whether the PC is inside the prolog.
    let func_start_va = image_base + u64::from(begin_rva);
    let in_prolog =
        control_pc >= func_start_va && (control_pc - func_start_va) < size_of_prolog as u64;
    let prolog_offset = if in_prolog {
        (control_pc - func_start_va) as usize
    } else {
        usize::MAX // treat as past-prolog: all codes apply
    };

    // If a frame pointer is established, the RSP base for this frame is
    //   frame_register - frame_offset * 16
    // We compute it here for use by UWOP_SET_FPREG.
    let fp_rsp_base = if frame_register != 0 {
        let fp_val = unsafe { ctx_read(ctx, ctx_reg_offset(frame_register)) };
        fp_val.wrapping_sub(u64::from(frame_offset) * 16)
    } else {
        0
    };

    // SAFETY: The UNWIND_CODE array starts at byte 4 of UNWIND_INFO.
    let codes = unsafe { ui.add(4).cast::<u16>() };

    let mut i = 0usize;
    while i < count_of_codes {
        let code = unsafe { codes.add(i).read_unaligned() };
        let code_offset = (code & 0xFF) as usize; // OffsetInProlog
        let unwind_op = ((code >> 8) & 0x0F) as u8;
        let op_info = ((code >> 12) & 0x0F) as u8;

        // Number of additional u16 slots consumed by this code entry
        let extra_slots: usize = match (unwind_op, op_info) {
            (UWOP_ALLOC_LARGE, 0) | (UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128, _) => 1,
            (UWOP_ALLOC_LARGE, 1..) | (UWOP_SAVE_NONVOL_FAR | UWOP_SAVE_XMM128_FAR, _) => 2,
            _ => 0,
        };

        // Bounds check: ensure the extra slots are within the codes array.
        // Malformed unwind info could otherwise cause out-of-bounds reads.
        if i + extra_slots >= count_of_codes && extra_slots > 0 {
            // Malformed unwind info; skip the rest of the codes and return no handler.
            break;
        }

        // In the prolog, skip codes for instructions not yet executed
        // (code_offset is the offset of the *next* instruction after this one,
        //  so the instruction has executed when prolog_offset >= code_offset).
        if in_prolog && prolog_offset < code_offset {
            i += 1 + extra_slots;
            continue;
        }

        match unwind_op {
            UWOP_PUSH_NONVOL => {
                // Prolog: push reg  →  unwind: reg = [RSP], RSP += 8
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                let val = unsafe { (rsp as *const u64).read_unaligned() };
                let reg_off = ctx_reg_offset(op_info);
                unsafe {
                    ctx_write(ctx, reg_off, val);
                    ctx_write(ctx, CTX_RSP, rsp + 8);
                }
                i += 1;
            }
            UWOP_ALLOC_LARGE => {
                let size = if op_info == 0 {
                    let next = unsafe { codes.add(i + 1).read_unaligned() };
                    u64::from(next) * 8
                } else {
                    let lo = unsafe { codes.add(i + 1).read_unaligned() };
                    let hi = unsafe { codes.add(i + 2).read_unaligned() };
                    u64::from(lo) | (u64::from(hi) << 16)
                };
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                unsafe { ctx_write(ctx, CTX_RSP, rsp + size) };
                i += 1 + extra_slots;
            }
            UWOP_ALLOC_SMALL => {
                // Prolog: sub rsp, (op_info+1)*8  →  unwind: RSP += (op_info+1)*8
                let size = (u64::from(op_info) + 1) * 8;
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                unsafe { ctx_write(ctx, CTX_RSP, rsp + size) };
                i += 1;
            }
            UWOP_SET_FPREG => {
                // Prolog: lea frame_reg, [rsp + frame_offset*16]
                // Unwind: RSP = frame_reg - frame_offset*16
                //
                // Wine's RtlVirtualUnwind also sets `*frame_ret = frame` here,
                // making the EstablisherFrame equal to the body RSP (the RSP
                // value right after the prolog completes).  This is critical for
                // MSVC catch funclets which receive EstablisherFrame in RDX and
                // reconstruct the parent function's frame pointer from it.
                //
                // Only apply when a valid frame pointer exists (frame_register != 0).
                // If fp_rsp_base is 0 the UNWIND_INFO is malformed; skip to avoid
                // setting RSP to 0 and crashing on the subsequent return-address pop.
                if fp_rsp_base != 0 {
                    unsafe { ctx_write(ctx, CTX_RSP, fp_rsp_base) };
                    if !establisher_frame_out.is_null() {
                        unsafe { *establisher_frame_out = fp_rsp_base };
                    }
                }
                i += 1;
            }
            UWOP_SAVE_NONVOL => {
                // Prolog: mov [rsp + slot*8], reg  →  unwind: reg = [rsp + slot*8]
                let slot = unsafe { codes.add(i + 1).read_unaligned() };
                let offset = u64::from(slot) * 8;
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                let val = unsafe { ((rsp + offset) as *const u64).read_unaligned() };
                let reg_off = ctx_reg_offset(op_info);
                unsafe { ctx_write(ctx, reg_off, val) };
                i += 2;
            }
            UWOP_SAVE_NONVOL_FAR => {
                // Prolog: mov [rsp + offset], reg  (large offset)
                let lo = unsafe { codes.add(i + 1).read_unaligned() };
                let hi = unsafe { codes.add(i + 2).read_unaligned() };
                let offset = u64::from(lo) | (u64::from(hi) << 16);
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                let val = unsafe { ((rsp + offset) as *const u64).read_unaligned() };
                let reg_off = ctx_reg_offset(op_info);
                unsafe { ctx_write(ctx, reg_off, val) };
                i += 3;
            }
            UWOP_SAVE_XMM128 => {
                // On Windows x64, XMM6–XMM15 are non-volatile and their saves are
                // described via UWOP_SAVE_XMM128 / UWOP_SAVE_XMM128_FAR entries.
                //
                // This unwinder reconstructs only integer register state (general-purpose
                // registers, RIP, RSP) and intentionally does not restore XMM register
                // contents into the CONTEXT.  XMM state in the produced CONTEXT may
                // therefore be inaccurate.  For stack-frame reconstruction and exception
                // dispatch this is acceptable; correct XMM state would only matter for
                // a full context-restore to resume execution mid-function.
                i += 2;
            }
            UWOP_SAVE_XMM128_FAR => {
                // See UWOP_SAVE_XMM128 above: XMM register state is intentionally not
                // restored; we only advance past the opcode and its two-slot offset.
                i += 3;
            }
            UWOP_PUSH_MACHFRAME => {
                // Machine exception frame pushed onto the stack:
                // [optional error code (8 bytes if op_info==1)], RIP, CS, RFLAGS, RSP, SS
                let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
                let rip_addr = if op_info == 1 { rsp + 8 } else { rsp };
                let rip = unsafe { (rip_addr as *const u64).read_unaligned() };
                // RSP is 3 slots after RIP (CS + RFLAGS = 2 × 8 bytes, then RSP)
                let new_rsp = unsafe { ((rip_addr + 24) as *const u64).read_unaligned() };
                unsafe {
                    ctx_write(ctx, CTX_RIP, rip);
                    ctx_write(ctx, CTX_RSP, new_rsp);
                }
                if !establisher_frame_out.is_null() {
                    unsafe { *establisher_frame_out = new_rsp }
                }
                if !handler_data_out.is_null() {
                    unsafe { *handler_data_out = core::ptr::null_mut() }
                }
                return core::ptr::null_mut();
            }
            _ => {
                i += 1;
            }
        }
    }

    // After applying all unwind codes, pop the return address.
    let rsp = unsafe { ctx_read(ctx, CTX_RSP) };
    let return_addr = unsafe { (rsp as *const u64).read_unaligned() };
    unsafe {
        ctx_write(ctx, CTX_RIP, return_addr);
        ctx_write(ctx, CTX_RSP, rsp + 8);
    }
    // For functions WITHOUT a frame register, the establisher frame is the
    // RSP after all unwind codes (before popping the return address).
    // For functions WITH a frame register, UWOP_SET_FPREG already wrote
    // the correct establisher frame (body RSP) above — do not overwrite it.
    if !establisher_frame_out.is_null() && frame_register == 0 {
        unsafe { *establisher_frame_out = rsp }
    }

    // ---- Determine the language-specific handler ----
    if flags & UNW_FLAG_CHAININFO != 0 {
        // UNW_FLAG_CHAININFO: after the codes (aligned to 4 bytes) lies another
        // RUNTIME_FUNCTION that chains to a parent function's unwind info.
        // Recursively apply the chained entry; do NOT return a handler from here.
        let codes_bytes = count_of_codes * 2;
        let chain_offset = (4 + codes_bytes + 3) & !3; // round up to 4-byte boundary
        let chain_rf = unsafe { ui.add(chain_offset).cast::<u32>() };
        let chain_begin = unsafe { chain_rf.read_unaligned() };
        let chain_unwind = unsafe { chain_rf.add(2).read_unaligned() };

        return unsafe {
            apply_unwind_info(
                image_base,
                chain_unwind,
                control_pc,
                chain_begin,
                ctx,
                handler_data_out,
                // Don't overwrite establisher_frame with chained frame
                core::ptr::null_mut(),
            )
        };
    }

    if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
        // The exception handler RVA follows the codes, aligned to 4 bytes.
        let codes_bytes = count_of_codes * 2;
        let handler_slot_offset = (4 + codes_bytes + 3) & !3;
        let handler_rva_ptr = unsafe { ui.add(handler_slot_offset).cast::<u32>() };
        let handler_rva = unsafe { handler_rva_ptr.read_unaligned() };
        if handler_rva != 0 {
            // HandlerData immediately follows the handler RVA DWORD.
            if !handler_data_out.is_null() {
                unsafe {
                    *handler_data_out = ui
                        .add(handler_slot_offset + 4)
                        .cast_mut()
                        .cast::<core::ffi::c_void>();
                }
            }
            return (image_base + u64::from(handler_rva)) as *mut core::ffi::c_void;
        }
    }

    core::ptr::null_mut()
}

/// SCOPE_TABLE entry for `__C_specific_handler`.
///
/// Each scope record describes one `__try` region inside a function and its
/// associated `__except` filter / handler or `__finally` block.
///
/// ```text
/// struct SCOPE_TABLE_ENTRY {
///     ULONG BeginAddress;   // RVA of __try block start
///     ULONG EndAddress;     // RVA of __try block end
///     ULONG HandlerAddress; // RVA of filter (__except) or handler (__finally)
///     ULONG JumpTarget;     // RVA of __except body; 0 for __finally
/// };
/// struct SCOPE_TABLE {
///     ULONG Count;
///     SCOPE_TABLE_ENTRY ScopeRecord[1]; // variable length
/// };
/// ```
#[repr(C)]
struct ScopeTableEntry {
    begin_address: u32,
    end_address: u32,
    handler_address: u32,
    jump_target: u32,
}

/// C-language exception handler (`__C_specific_handler`)
///
/// Implements `__try`/`__except`/`__finally` for Windows x64 by walking the
/// SCOPE_TABLE attached to the function's UNWIND_INFO.
///
/// **Search phase** (no `EXCEPTION_UNWINDING` flag):
///   For each scope whose `[BeginAddress, EndAddress)` contains the control PC:
///   - If `JumpTarget != 0` (an `__except` block), call the filter expression
///     at `HandlerAddress`.  If the filter returns `EXCEPTION_EXECUTE_HANDLER`
///     (1), initiate unwind to `JumpTarget`.
///   - If `JumpTarget == 0` (a `__finally` block), skip it during the search
///     phase; it will be called during the unwind phase.
///
/// **Unwind phase** (`EXCEPTION_UNWINDING` is set):
///   For each scope containing the control PC whose `JumpTarget == 0`:
///   call the termination handler at `HandlerAddress`.
///
/// # Safety
/// All pointer arguments must be valid or NULL.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn kernel32___C_specific_handler(
    exception_record: *mut core::ffi::c_void,
    establisher_frame: u64,
    context_record: *mut core::ffi::c_void,
    dispatcher_context: *mut core::ffi::c_void,
) -> i32 {
    if exception_record.is_null() || dispatcher_context.is_null() {
        return 1; // EXCEPTION_CONTINUE_SEARCH
    }

    let exc = exception_record.cast::<ExceptionRecord>();
    let dc = dispatcher_context.cast::<DispatcherContext>();

    // SAFETY: dc is a valid DispatcherContext.
    let handler_data = unsafe { (*dc).handler_data };
    if handler_data.is_null() {
        return 1; // no scope table
    }

    // Read scope table count.
    // SAFETY: handler_data points to a SCOPE_TABLE.
    let scope_count = unsafe { (handler_data.cast::<u32>()).read_unaligned() } as usize;
    if scope_count == 0 {
        return 1;
    }

    // SAFETY: scope entries follow the count field.
    let scope_entries = unsafe { handler_data.cast::<u32>().add(1).cast::<ScopeTableEntry>() };

    let image_base = unsafe { (*dc).image_base };
    let control_pc = unsafe { (*dc).control_pc };
    let control_rva = (control_pc - image_base) as u32;

    let is_unwinding = unsafe { (*exc).exception_flags & EXCEPTION_UNWINDING } != 0;

    for i in 0..scope_count {
        // SAFETY: We trust that handler_data points to a valid SCOPE_TABLE
        // whose `Count` field matches the actual number of entries.  This
        // assumption is guaranteed by the PE loader having validated the
        // UNWIND_INFO and SCOPE_TABLE structures during image loading.
        let entry = unsafe { &*scope_entries.add(i) };

        if control_rva < entry.begin_address || control_rva >= entry.end_address {
            continue;
        }

        if is_unwinding {
            // Unwind phase: call __finally handlers (JumpTarget == 0).
            if entry.jump_target == 0 && entry.handler_address != 0 {
                // Termination handler signature:
                //   void handler(BOOLEAN abnormal_termination, u64 establisher_frame)
                type TerminationHandler = unsafe extern "win64" fn(u8, u64);
                let handler_addr = image_base + u64::from(entry.handler_address);
                let handler: TerminationHandler = unsafe { core::mem::transmute(handler_addr) };
                // abnormal_termination = TRUE (1) during unwind
                unsafe { handler(1, establisher_frame) };
            }
        } else {
            // Search phase: evaluate __except filters (JumpTarget != 0).
            if entry.jump_target != 0 && entry.handler_address != 0 {
                // Filter signature:
                //   LONG filter(EXCEPTION_POINTERS* ptrs, u64 establisher_frame)
                // We pass the exception record pointer as the EXCEPTION_POINTERS
                // (simplified; a full impl would build a proper EXCEPTION_POINTERS).
                type FilterExpression =
                    unsafe extern "win64" fn(*mut core::ffi::c_void, u64) -> i32;

                // Special case: HandlerAddress == 1 means EXCEPTION_EXECUTE_HANDLER constant.
                let filter_result = if entry.handler_address == 1 {
                    1 // EXCEPTION_EXECUTE_HANDLER
                } else {
                    let filter_addr = image_base + u64::from(entry.handler_address);
                    let filter: FilterExpression = unsafe { core::mem::transmute(filter_addr) };
                    unsafe { filter(exception_record, establisher_frame) }
                };

                if filter_result == 1 {
                    // EXCEPTION_EXECUTE_HANDLER: unwind to the __except body.
                    let target_ip = image_base + u64::from(entry.jump_target);
                    // SAFETY: RtlUnwindEx will transfer control to the __except body.
                    unsafe {
                        kernel32_RtlUnwindEx(
                            establisher_frame as *mut core::ffi::c_void,
                            target_ip as *mut core::ffi::c_void,
                            exception_record,
                            u64::from(exception_code_from_record(exc)) as *mut core::ffi::c_void,
                            context_record,
                            core::ptr::null_mut(),
                        );
                    }
                    // RtlUnwindEx never returns if it succeeds.
                    return 0; // EXCEPTION_CONTINUE_EXECUTION (fallback)
                } else if filter_result == -1 {
                    // EXCEPTION_CONTINUE_EXECUTION
                    return 0;
                }
                // filter_result == 0: EXCEPTION_CONTINUE_SEARCH — try next scope.
            }
        }
    }

    1 // EXCEPTION_CONTINUE_SEARCH
}

/// Extract the exception code from an `ExceptionRecord` pointer.
///
/// # Safety
/// `exc` must point to a valid `ExceptionRecord`.
unsafe fn exception_code_from_record(exc: *const ExceptionRecord) -> u32 {
    if exc.is_null() {
        0
    } else {
        unsafe { (*exc).exception_code }
    }
}

/// Set unhandled exception filter
///
/// Stores the filter but does not invoke it; returns the previous filter
/// (always NULL in this implementation).
///
/// # Safety
/// Safe to call with any argument including NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetUnhandledExceptionFilter(
    _filter: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    core::ptr::null_mut()
}

/// UnhandledExceptionFilter
///
/// Returns `EXCEPTION_CONTINUE_SEARCH` (0), indicating the exception should
/// continue propagating.
///
/// # Safety
/// Safe to call with any argument including NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnhandledExceptionFilter(
    _exception_info: *mut core::ffi::c_void,
) -> i32 {
    0
}

/// InitializeSListHead
///
/// Initializes a singly-linked list head by clearing its first pointer-sized
/// field to null.
///
/// # Safety
/// If `list_head` is non-null, it must point to writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeSListHead(list_head: *mut core::ffi::c_void) {
    if list_head.is_null() {
        return;
    }
    unsafe { (list_head.cast::<usize>()).write_unaligned(0) };
}

/// Raise an exception and dispatch it through the SEH handler chain.
///
/// Implements Windows x64 SEH phase-1 (search) walk: for each PE frame on
/// the guest call stack, calls `RtlLookupFunctionEntry` + `RtlVirtualUnwind`
/// to find a language-specific handler.  If the handler (e.g.
/// `__gxx_personality_seh0` for MinGW or `__CxxFrameHandler3` for MSVC)
/// finds a matching catch clause it will call `RtlUnwindEx` which transfers
/// control to the landing pad; that call never returns.
/// If no handler is found the process is aborted.
///
/// Exception codes recognized:
///   0x20474343 (STATUS_GCC_THROW)          – MinGW/GCC normal C++ throw
///   0x21474343 (STATUS_GCC_UNWIND)         – MinGW/GCC forced unwind
///   0x22474343 (STATUS_GCC_FORCED)         – MinGW/GCC forced unwind (alt)
///   0xE06D7363 (STATUS_MSVC_CPP_EXCEPTION) – MSVC C++ throw (`_CxxThrowException`)
///
/// Ref: Wine `dlls/ntdll/exception.c`, ReactOS `sdk/lib/rtl/exception.c`.
///
/// # Safety
/// Never returns normally; either control is transferred to a catch landing
/// pad or the process aborts.
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn kernel32_RaiseException(
    exception_code: u32,
    exception_flags: u32,
    number_parameters: u32,
    arguments: *const usize,
) -> ! {
    // Dispatch C++ exceptions (GCC/MinGW and MSVC) through the SEH walk.
    // Abort all other exception codes (hardware faults, etc.).
    if exception_code != STATUS_GCC_THROW
        && exception_code != STATUS_GCC_UNWIND
        && exception_code != STATUS_GCC_FORCED
        && exception_code != STATUS_MSVC_CPP_EXCEPTION
    {
        eprintln!("Windows exception raised (code: {exception_code:#x}) - aborting");
        std::process::abort();
    }

    // ── Handle STATUS_GCC_UNWIND / STATUS_GCC_FORCED directly ──────────────
    //
    // When `_GCC_specific_handler` finds a matching catch clause during the
    // Phase 1 search, it calls `RaiseException(STATUS_GCC_UNWIND, ...)`.
    // On real Windows the OS exception dispatcher would re-walk the native
    // stack, reach the target frame, and `_GCC_specific_handler` there would
    // call `RtlUnwindEx` to do the Phase 2 cleanup walk.
    //
    // In our implementation, however, the Phase 1 walk was done from Rust
    // code inside `seh_walk_stack_dispatch`.  When `_GCC_specific_handler`
    // is called from that walk (via trampoline) and then raises
    // `STATUS_GCC_UNWIND`, the stack between here and the target frame
    // contains Rust frames that have no `.pdata` entries.  A new Phase 1
    // walk from here would exit the PE on the very first Rust frame,
    // failing to reach the target.
    //
    // The fix: short-circuit `STATUS_GCC_UNWIND` by extracting the target
    // frame and target IP from `ExceptionInformation` and calling
    // `kernel32_RtlUnwindEx` directly.  This is semantically identical to
    // what `_GCC_specific_handler` would do after the Phase 1 walk reached
    // the target frame — we just skip the walk.
    //
    // This is handled in a separate `#[cold]` function so the additional
    // stack allocations do not inflate `kernel32_RaiseException`'s frame
    // and push the trampoline return address outside the 2048-byte scan
    // window used by `seh_find_pe_frame_on_stack`.
    if (exception_code == STATUS_GCC_UNWIND || exception_code == STATUS_GCC_FORCED)
        && !arguments.is_null()
        && number_parameters >= 3
    {
        // SAFETY: caller guarantees `arguments` is valid for `number_parameters`.
        unsafe {
            handle_gcc_unwind(
                exception_code,
                exception_flags,
                number_parameters,
                arguments,
            )
        };
    }

    // ── Locate the guest frame that called RaiseException ──────────────────
    // The trampoline prologue is: push rdi; push rsi; sub rsp,8; ...
    // So from inside our Rust function the guest return address lives somewhere
    // above our current RSP.  We scan upward for the first pointer that falls
    // within the loaded PE image.
    let rust_rsp: usize;
    let nv_rbx: u64;
    let nv_rbp_or_frame: u64;
    let nv_r12: u64;
    let nv_r13: u64;
    let nv_r14: u64;
    let nv_r15: u64;
    // SAFETY: Capturing RSP and callee-saved registers (SysV ABI: RBX, R12-R15).
    // These registers are callee-saved in both Windows x64 and SysV ABIs, so
    // their values match the guest PE's values at the RaiseException call site.
    // For RBP: the Rust compiler does NOT use a frame pointer for this
    // `extern "C"` function (it only does `sub rsp, N`), so RBP still holds
    // the PE's callee-saved RBP value directly — no dereference needed.
    // RSI and RDI are captured from the trampoline frame.
    unsafe {
        core::arch::asm!(
            "mov {rsp_out}, rsp",
            "mov {rbx_out}, rbx",
            "mov {rbp_out}, rbp",
            "mov {r12_out}, r12",
            "mov {r13_out}, r13",
            "mov {r14_out}, r14",
            "mov {r15_out}, r15",
            rsp_out = out(reg) rust_rsp,
            rbx_out = out(reg) nv_rbx,
            rbp_out = out(reg) nv_rbp_or_frame,
            r12_out = out(reg) nv_r12,
            r13_out = out(reg) nv_r13,
            r14_out = out(reg) nv_r14,
            r15_out = out(reg) nv_r15,
            options(nostack, readonly),
        );
    }

    let Some(pe_frame) = seh_find_pe_frame_on_stack(rust_rsp) else {
        eprintln!(
            "RaiseException(0x{exception_code:08x}): could not find PE frame on stack – aborting"
        );
        std::process::abort();
    };
    let start_rip = pe_frame.control_pc;
    let start_rsp = pe_frame.guest_rsp;

    // RBP was read directly from the register in the inline asm above.
    // Since the Rust compiler does not use a frame pointer for this function
    // (prologue is `sub rsp, N` without `push rbp`), RBP still holds the
    // PE's callee-saved value at the RaiseException call site.
    let nv_regs = NonVolatileRegs {
        rbx: nv_rbx,
        rbp: nv_rbp_or_frame,
        rsi: pe_frame.guest_rsi,
        rdi: pe_frame.guest_rdi,
        r12: nv_r12,
        r13: nv_r13,
        r14: nv_r14,
        r15: nv_r15,
    };

    // ── Stash the throw-site context for RtlUnwindEx ───────────────────────
    // Wine's RtlUnwindEx calls RtlCaptureContext internally to obtain the
    // current (throw-site) context and starts the cleanup walk from there,
    // visiting all intermediate frames between the throw and the catch.
    // We replicate that by storing the throw-site PC/SP here, which
    // kernel32_RtlUnwindEx reads to initialise its walk context instead of
    // starting from the (already-at-target) catch-frame context it receives.
    THROW_SITE_CTX.with(|c| {
        c.set(Some(ThrowSiteContext {
            rip: start_rip,
            rsp: start_rsp,
            rbx: nv_regs.rbx,
            rbp: nv_regs.rbp,
            rsi: nv_regs.rsi,
            rdi: nv_regs.rdi,
            r12: nv_regs.r12,
            r13: nv_regs.r13,
            r14: nv_regs.r14,
            r15: nv_regs.r15,
        }));
    });

    // ── Build the EXCEPTION_RECORD ──────────────────────────────────────────
    let exc_layout = alloc::Layout::new::<ExceptionRecord>();
    // SAFETY: Layout is non-zero.
    let exc_ptr = unsafe { alloc::alloc_zeroed(exc_layout) }.cast::<ExceptionRecord>();
    if exc_ptr.is_null() {
        std::process::abort();
    }
    // SAFETY: exc_ptr is freshly allocated and non-null.
    unsafe {
        (*exc_ptr).exception_code = exception_code;
        (*exc_ptr).exception_flags = exception_flags & !EXCEPTION_UNWINDING;
        (*exc_ptr).exception_record = core::ptr::null_mut();
        (*exc_ptr).exception_address = start_rip as *mut core::ffi::c_void;
        (*exc_ptr).number_parameters = number_parameters.min(15);
        if !arguments.is_null() {
            let n = (*exc_ptr).number_parameters as usize;
            for i in 0..n {
                (*exc_ptr).exception_information[i] = *arguments.add(i);
            }
        }
    }

    // ── Phase 1: search for a handler ──────────────────────────────────────
    let found = unsafe { seh_walk_stack_dispatch(exc_ptr, start_rip, start_rsp, 1, &nv_regs) };

    // SAFETY: exc_ptr was allocated above.
    unsafe { alloc::dealloc(exc_ptr.cast::<u8>(), exc_layout) };

    if !found {
        eprintln!("Unhandled C++ exception (code: {exception_code:#x}) – aborting");
        std::process::abort();
    }

    // seh_walk_stack_dispatch returns `true` only when a handler called
    // RtlUnwindEx, which never returns.  We should never reach here.
    std::process::abort();
}

/// Handle `STATUS_GCC_UNWIND` / `STATUS_GCC_FORCED` by directly calling
/// `RtlUnwindEx` with the target information from `ExceptionInformation`.
///
/// This is `#[cold]` and `#[inline(never)]` to prevent the compiler from
/// merging its stack frame into `kernel32_RaiseException`, which would
/// inflate the parent's frame size and push the trampoline return address
/// outside the 2048-byte scan window of `seh_find_pe_frame_on_stack`.
///
/// # Safety
/// `arguments` must be valid for at least `number_parameters` elements.
#[cold]
#[inline(never)]
unsafe fn handle_gcc_unwind(
    exception_code: u32,
    exception_flags: u32,
    number_parameters: u32,
    arguments: *const usize,
) -> ! {
    let exc_layout = alloc::Layout::new::<ExceptionRecord>();
    // SAFETY: Layout is non-zero.
    let exc_ptr = unsafe { alloc::alloc_zeroed(exc_layout) }.cast::<ExceptionRecord>();
    if exc_ptr.is_null() {
        std::process::abort();
    }
    // SAFETY: exc_ptr is freshly allocated and non-null.
    unsafe {
        (*exc_ptr).exception_code = exception_code;
        (*exc_ptr).exception_flags = exception_flags;
        (*exc_ptr).exception_record = core::ptr::null_mut();
        (*exc_ptr).exception_address = core::ptr::null_mut();
        (*exc_ptr).number_parameters = number_parameters.min(15);
        let n = (*exc_ptr).number_parameters as usize;
        for i in 0..n {
            (*exc_ptr).exception_information[i] = *arguments.add(i);
        }
    }

    // ExceptionInformation layout (set by `_GCC_specific_handler`):
    //   [0] = `_Unwind_Exception*` (return value for RAX at landing pad)
    //   [1] = establisher frame (target frame address)
    //   [2] = target IP (landing pad address)
    //   [3] = context_record pointer
    let uwexc_ptr = unsafe { *arguments } as *mut core::ffi::c_void;
    let target_frame = unsafe { *arguments.add(1) } as *mut core::ffi::c_void;
    let target_ip = unsafe { *arguments.add(2) } as *mut core::ffi::c_void;

    // Allocate a CONTEXT for the RtlUnwindEx call, seeded from the
    // throw-site context (so the cleanup walk starts at the throw frame
    // and visits all intermediate frames for destructor cleanup).
    let ctx_layout = alloc::Layout::from_size_align(CTX_SIZE, 16).expect("CTX layout is valid");
    // SAFETY: layout is non-zero.
    let ctx = unsafe { alloc::alloc_zeroed(ctx_layout) };
    if ctx.is_null() {
        std::process::abort();
    }
    // Use the stashed throw-site context if available, then clear it so
    // nested RtlUnwindEx calls (from intermediate cleanup handlers) use
    // their caller-supplied context instead of re-using the stale throw-site.
    let throw_site = THROW_SITE_CTX.with(|c| {
        let val = c.get();
        c.set(None);
        val
    });
    if let Some(ts) = throw_site {
        unsafe {
            ctx_write(ctx, CTX_RIP, ts.rip);
            ctx_write(ctx, CTX_RSP, ts.rsp);
            ctx_write(ctx, CTX_RBX, ts.rbx);
            ctx_write(ctx, CTX_RBP, ts.rbp);
            ctx_write(ctx, CTX_RSI, ts.rsi);
            ctx_write(ctx, CTX_RDI, ts.rdi);
            ctx_write(ctx, CTX_R12, ts.r12);
            ctx_write(ctx, CTX_R13, ts.r13);
            ctx_write(ctx, CTX_R14, ts.r14);
            ctx_write(ctx, CTX_R15, ts.r15);
        }
    }

    // SAFETY: all pointers are valid; RtlUnwindEx does not return on
    // success — it jumps to the landing pad.
    unsafe {
        kernel32_RtlUnwindEx(
            target_frame,
            target_ip,
            exc_ptr.cast::<core::ffi::c_void>(),
            uwexc_ptr,
            ctx.cast::<core::ffi::c_void>(),
            core::ptr::null_mut(),
        );
    }
    // RtlUnwindEx should never return.
    std::process::abort();
}

/// Capture the current CPU context into a Windows CONTEXT structure
///
/// Captures non-volatile registers reliably (they are preserved across function
/// calls) and RSP/RIP to the values current at the call site.
/// Volatile registers are captured best-effort.
///
/// # Safety
/// `context` must point to a writable buffer of at least CTX_SIZE (1232) bytes.
/// Passing NULL is safe; the function returns immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlCaptureContext(context: *mut core::ffi::c_void) {
    if context.is_null() {
        return;
    }

    // Zero the entire CONTEXT structure first.
    // SAFETY: caller guarantees the pointer is valid for CTX_SIZE bytes.
    unsafe { core::ptr::write_bytes(context.cast::<u8>(), 0, CTX_SIZE) };

    // Capture register values using a single base-register operand.
    // Non-volatile registers (RBX, RBP, RSI, RDI, R12–R15) reliably hold
    // their caller-visible values at this point.  RSP and RIP are computed
    // from the stack frame.  Volatile registers are included best-effort.
    // SAFETY: `context` points to a zeroed CTX_SIZE-byte buffer (see above).
    unsafe {
        core::arch::asm!(
            "mov [{ctx} + 0x90], rbx",   // Rbx
            "mov [{ctx} + 0xA0], rbp",   // Rbp
            "mov [{ctx} + 0xA8], rsi",   // Rsi
            "mov [{ctx} + 0xB0], rdi",   // Rdi
            "mov [{ctx} + 0xD8], r12",   // R12
            "mov [{ctx} + 0xE0], r13",   // R13
            "mov [{ctx} + 0xE8], r14",   // R14
            "mov [{ctx} + 0xF0], r15",   // R15
            // RSP: caller's RSP = current RSP + 8 (for the return address pushed by CALL)
            "lea rax, [rsp + 8]",
            "mov [{ctx} + 0x98], rax",   // Rsp
            // RIP: return address sitting at the top of our stack
            "mov rax, [rsp]",
            "mov [{ctx} + 0xF8], rax",   // Rip
            ctx = in(reg) context,
            out("rax") _,
            options(nostack),
        );
    }
}

/// Lookup the `IMAGE_RUNTIME_FUNCTION_ENTRY` for the given program counter
///
/// Searches the registered `.pdata` exception table for a RUNTIME_FUNCTION
/// whose `[BeginAddress, EndAddress)` range contains `control_pc`.
///
/// On success, sets `*image_base` to the image load address and returns a
/// pointer to the matching entry inside the loaded image's memory.
/// Returns NULL if no entry is found (e.g. no exception table registered,
/// or `control_pc` is outside all known functions).
///
/// # Safety
/// `image_base` may be NULL (the output is skipped); `history_table` is unused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlLookupFunctionEntry(
    control_pc: u64,
    image_base: *mut u64,
    _history_table: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Each RUNTIME_FUNCTION entry is 12 bytes: BeginAddress(4), EndAddress(4), UnwindInfoAddress(4)
    const RF_SIZE: u32 = 12;

    let guard = EXCEPTION_TABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(ref tbl) = *guard else {
        return core::ptr::null_mut();
    };

    // The RVA of control_pc within this image
    let Some(rva) = control_pc.checked_sub(tbl.image_base) else {
        return core::ptr::null_mut();
    };
    // PE RVAs are 32-bit; if the delta exceeds u32::MAX the PC is outside this image.
    if rva > u64::from(u32::MAX) {
        return core::ptr::null_mut();
    }
    let rva = rva as u32;

    let num_entries = tbl.pdata_size / RF_SIZE;

    for idx in 0..num_entries {
        let entry_ptr =
            (tbl.image_base + u64::from(tbl.pdata_rva) + u64::from(idx * RF_SIZE)) as *const u32;
        // SAFETY: The .pdata section is within the loaded image memory.
        let begin = unsafe { entry_ptr.read_unaligned() };
        let end = unsafe { entry_ptr.add(1).read_unaligned() };

        if rva >= begin && rva < end {
            if !image_base.is_null() {
                unsafe { *image_base = tbl.image_base }
            }
            return entry_ptr as *mut core::ffi::c_void;
        }
    }

    core::ptr::null_mut()
}

/// Perform stack unwinding
///
/// Walks up one stack frame using the information in `function_entry`'s
/// `UNWIND_INFO`.  On return, `context_record` reflects the caller's register
/// state and `*establisher_frame` is set to the frame's RSP before the return
/// address was popped.
///
/// If the function has a registered exception/termination handler, a pointer
/// to it is returned and `*handler_data` is set to the handler-specific data
/// (e.g. the `SCOPE_TABLE` for `__C_specific_handler`).
///
/// Returns NULL if no handler is registered for this frame.
///
/// # Safety
/// - `function_entry` must be a pointer to a valid RUNTIME_FUNCTION in the loaded image.
/// - `context_record` must point to a valid, writable Windows CONTEXT structure.
/// - `handler_data` and `establisher_frame` may be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RtlVirtualUnwind(
    _handler_type: u32,
    image_base: u64,
    control_pc: u64,
    function_entry: *mut core::ffi::c_void,
    context_record: *mut core::ffi::c_void,
    handler_data: *mut *mut core::ffi::c_void,
    establisher_frame: *mut u64,
    _context_pointers: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    if function_entry.is_null() || context_record.is_null() {
        return core::ptr::null_mut();
    }

    // Read the RUNTIME_FUNCTION fields: BeginAddress, EndAddress, UnwindInfoAddress
    let rf = function_entry.cast::<u32>();
    let begin_rva = unsafe { rf.read_unaligned() };
    let unwind_info_rva = unsafe { rf.add(2).read_unaligned() };

    // SAFETY: image_base is the load address, unwind_info_rva is within the image.
    unsafe {
        apply_unwind_info(
            image_base,
            unwind_info_rva,
            control_pc,
            begin_rva,
            context_record.cast::<u8>(),
            handler_data,
            establisher_frame,
        )
    }
}

/// Perform full stack unwinding to a target frame (phase 2)
///
/// Called by language-specific handlers (e.g. `__gxx_personality_seh0`) when
/// a catch clause has been selected.  This implements the Windows x64
/// `RtlUnwindEx` semantics modelled after Wine and ReactOS:
///
/// 1. Set `EXCEPTION_UNWINDING` on the exception record.
/// 2. Walk from the current PC/SP up to `target_frame`, calling every
///    intermediate frame's `UHANDLER` (cleanup/destructor handler) with
///    `EXCEPTION_UNWINDING` set.  When reaching `target_frame`, also set
///    `EXCEPTION_TARGET_UNWIND`.
/// 3. Fix up the context with `target_ip` (landing pad) and `return_value`
///    (the `_Unwind_Exception*` or exception code), then restore registers
///    and jump.
///
/// This two-phase approach is critical for C++ exception handling: without
/// it, destructors in intermediate frames between the throw site and the
/// catch clause would be skipped.
///
/// # Safety
/// - `context_record` must be non-NULL and point to a valid, writable `CONTEXT`.
/// - After a successful unwind this function never returns; execution resumes
///   at the landing pad.
/// - All pointer arguments may be NULL except `context_record`.
///
/// # Panics
/// Panics if the internal CONTEXT layout computation fails (should never
/// happen in practice).
#[unsafe(no_mangle)]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn kernel32_RtlUnwindEx(
    target_frame: *mut core::ffi::c_void,
    target_ip: *mut core::ffi::c_void,
    exception_record: *mut core::ffi::c_void,
    return_value: *mut core::ffi::c_void,
    context_record: *mut core::ffi::c_void,
    _history_table: *mut core::ffi::c_void,
) {
    // Language handler function type (Windows x64 ABI).
    type ExceptionRoutine =
        unsafe extern "win64" fn(*mut ExceptionRecord, u64, *mut u8, *mut DispatcherContext) -> i32;

    if context_record.is_null() {
        return;
    }

    let ctx = context_record.cast::<u8>();

    // ── Step 1: Mark the exception as unwinding ────────────────────────────
    if !exception_record.is_null() {
        // SAFETY: caller guarantees exception_record is a valid EXCEPTION_RECORD.
        let exc = exception_record.cast::<ExceptionRecord>();
        unsafe {
            (*exc).exception_flags |= EXCEPTION_UNWINDING;
        }
    }

    let target_frame_addr = target_frame as u64;

    // ── Step 2: Phase-2 cleanup walk ──────────────────────────────────────
    //
    // Walk from the current context toward `target_frame`, calling every
    // intermediate frame's UHANDLER (cleanup/destructor handler) with
    // `EXCEPTION_UNWINDING` set.
    //
    // We allocate a separate walk context so `ctx` (the caller's original
    // context) is preserved for the final landing-pad jump.
    //
    // After each INTERMEDIATE frame we copy `walk_ctx → ctx` (matching
    // Wine's `*context = new_context;`), so that when we break at the target
    // frame `ctx` has the non-volatile registers restored by unwinding all
    // intermediate frames.
    let walk_ctx_layout =
        alloc::Layout::from_size_align(CTX_SIZE, 16).expect("CTX layout is valid");
    // SAFETY: layout is non-zero.
    let walk_ctx = unsafe { alloc::alloc_zeroed(walk_ctx_layout) };
    // Save target frame metadata so we can fix up the body frame register
    // after the loop (image_base + function_entry are needed by
    // `compute_body_frame_reg`).
    let mut target_fe: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut target_image_base: u64 = 0;
    let mut target_establisher: u64 = 0;
    if walk_ctx.is_null() {
        eprintln!("RtlUnwindEx: failed to allocate walk context — skipping cleanup walk");
    } else {
        // ── Seed walk_ctx from the throw site, not the catch frame ──────────
        //
        // Wine's RtlUnwindEx calls RtlCaptureContext internally to obtain the
        // current execution context (inside RtlUnwindEx itself, deep in the
        // call stack at the throw site) and walks OUTWARD from there to
        // `target_frame`, visiting every intermediate frame and calling its
        // cleanup handler.
        //
        // In our implementation RtlUnwindEx is a Rust function; we cannot
        // easily call RtlCaptureContext here (the Rust frames aren't in the PE
        // .pdata).  Instead, kernel32_RaiseException stashes the throw-site
        // PC/SP in a thread-local (THROW_SITE_CTX) which we read here.
        //
        // If no stashed context is available (e.g. called directly from Rust
        // without going through RaiseException) we fall back to the
        // caller-supplied context_record as before.
        //
        // Do NOT clear THROW_SITE_CTX here: the GCC exception protocol may
        // call RtlUnwindEx from _GCC_specific_handler's search path, then
        // later raise STATUS_GCC_UNWIND which is handled by
        // `handle_gcc_unwind` — that function also needs the throw-site
        // context.  Clearing here would race with the GCC protocol.
        let throw_site = THROW_SITE_CTX.with(std::cell::Cell::get);
        if let Some(ts) = throw_site {
            // SAFETY: walk_ctx is a freshly zeroed CTX_SIZE-byte allocation.
            unsafe {
                ctx_write(walk_ctx, CTX_RIP, ts.rip);
                ctx_write(walk_ctx, CTX_RSP, ts.rsp);
                ctx_write(walk_ctx, CTX_RBX, ts.rbx);
                ctx_write(walk_ctx, CTX_RBP, ts.rbp);
                ctx_write(walk_ctx, CTX_RSI, ts.rsi);
                ctx_write(walk_ctx, CTX_RDI, ts.rdi);
                ctx_write(walk_ctx, CTX_R12, ts.r12);
                ctx_write(walk_ctx, CTX_R13, ts.r13);
                ctx_write(walk_ctx, CTX_R14, ts.r14);
                ctx_write(walk_ctx, CTX_R15, ts.r15);
            }
        } else {
            // Fallback: copy the caller-supplied context into the walk buffer.
            // SAFETY: both buffers are CTX_SIZE bytes.
            unsafe { core::ptr::copy_nonoverlapping(ctx, walk_ctx, CTX_SIZE) };
        }

        let mut max_frames: u32 = 256;
        loop {
            max_frames -= 1;
            if max_frames == 0 {
                eprintln!(
                    "RtlUnwindEx: frame walk limit (256) exceeded without reaching target frame"
                );
                break;
            }

            // SAFETY: walk_ctx is valid.
            let control_pc = unsafe { ctx_read(walk_ctx, CTX_RIP) };
            if control_pc == 0 {
                break;
            }

            let mut image_base: u64 = 0;
            // SAFETY: RtlLookupFunctionEntry is safe with valid PC.
            let fe = unsafe {
                kernel32_RtlLookupFunctionEntry(
                    control_pc,
                    &raw mut image_base,
                    core::ptr::null_mut(),
                )
            };
            if fe.is_null() {
                // Outside the PE — pop the return address and continue.
                let rsp = unsafe { ctx_read(walk_ctx, CTX_RSP) };
                let ret_addr = unsafe { (rsp as *const u64).read_unaligned() };
                unsafe {
                    ctx_write(walk_ctx, CTX_RIP, ret_addr);
                    ctx_write(walk_ctx, CTX_RSP, rsp + 8);
                }
                // Non-PE frames don't update ctx — they are skipped.
                continue;
            }

            let mut handler_data: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut establisher_frame: u64 = 0;

            // SAFETY: fe and walk_ctx are valid.
            let lang_handler = unsafe {
                kernel32_RtlVirtualUnwind(
                    u32::from(UNW_FLAG_UHANDLER),
                    image_base,
                    control_pc,
                    fe,
                    walk_ctx.cast::<core::ffi::c_void>(),
                    &raw mut handler_data,
                    &raw mut establisher_frame,
                    core::ptr::null_mut(),
                )
            };

            // Check if we've reached or passed the target frame.
            if target_frame_addr != 0 && establisher_frame == target_frame_addr {
                // Target frame reached — set EXCEPTION_TARGET_UNWIND.
                if !exception_record.is_null() {
                    let exc = exception_record.cast::<ExceptionRecord>();
                    // SAFETY: exc is a valid ExceptionRecord.
                    unsafe {
                        (*exc).exception_flags |= EXCEPTION_TARGET_UNWIND;
                    }
                }

                // Save target frame info for body frame register fixup.
                target_fe = fe;
                target_image_base = image_base;
                target_establisher = establisher_frame;

                // Call the target frame's handler if present.
                if !lang_handler.is_null() && !exception_record.is_null() {
                    let mut dc = DispatcherContext {
                        control_pc,
                        image_base,
                        function_entry: fe,
                        establisher_frame,
                        target_ip: target_ip as u64,
                        context_record: ctx,
                        language_handler: lang_handler,
                        handler_data,
                        history_table: core::ptr::null_mut(),
                        scope_index: 0,
                        _fill0: 0,
                    };
                    let handler_fn: ExceptionRoutine =
                        unsafe { core::mem::transmute(lang_handler) };
                    // SAFETY: handler_fn is a valid PE function pointer.
                    unsafe {
                        handler_fn(
                            exception_record.cast::<ExceptionRecord>(),
                            establisher_frame,
                            ctx,
                            &raw mut dc,
                        );
                    }
                }
                break;
            }

            // Intermediate frame: call its UHANDLER if present.
            if !lang_handler.is_null() && !exception_record.is_null() {
                let mut dc = DispatcherContext {
                    control_pc,
                    image_base,
                    function_entry: fe,
                    establisher_frame,
                    target_ip: 0,
                    context_record: walk_ctx,
                    language_handler: lang_handler,
                    handler_data,
                    history_table: core::ptr::null_mut(),
                    scope_index: 0,
                    _fill0: 0,
                };
                let handler_fn: ExceptionRoutine = unsafe { core::mem::transmute(lang_handler) };
                // SAFETY: handler_fn is a valid PE function pointer.
                unsafe {
                    handler_fn(
                        exception_record.cast::<ExceptionRecord>(),
                        establisher_frame,
                        walk_ctx,
                        &raw mut dc,
                    );
                }
            }

            // Copy walk_ctx to ctx after each intermediate frame, matching
            // Wine's `*context = new_context;` at the end of each loop
            // iteration.  When we break at the target frame, ctx retains
            // the state from the previous iteration — exactly the registers
            // the catch landing pad expects (non-volatile regs restored
            // by intermediate frames' unwind info).
            // SAFETY: both buffers are CTX_SIZE bytes.
            unsafe { core::ptr::copy_nonoverlapping(walk_ctx, ctx, CTX_SIZE) };
        }

        // SAFETY: walk_ctx was allocated above.
        unsafe { alloc::dealloc(walk_ctx, walk_ctx_layout) };
    }

    // ── Step 3: Fix up the context for the landing pad ─────────────────────
    //
    // Determine the exception ABI so we can fix up registers correctly.
    let is_msvc_exception = !exception_record.is_null()
        && unsafe {
            (*exception_record.cast::<ExceptionRecord>()).exception_code
                == STATUS_MSVC_CPP_EXCEPTION
        };

    if is_msvc_exception {
        // MSVC C++ exception:
        //   RIP ← the context already has the continuation IP set by
        //          __CxxFrameHandler3 (which called the catch funclet and
        //          stored its return value in context->Rip). Do NOT override
        //          it with target_ip (which was the funclet address, not the
        //          continuation).
        //   RAX ← not meaningful for MSVC path (funclet returns continuation
        //          directly); set to 0.
        //   RDX ← not overridden (context already has correct registers from
        //          the unwind walk that __CxxFrameHandler3 used).
    } else {
        // GCC/MinGW C++ exception (or generic SEH):
        //   RIP ← target_ip (landing pad address set during Phase 1)
        //   RAX ← return_value (_Unwind_Exception* read by the landing pad)
        //   RDX ← ExceptionInformation[3] (type-selector index)
        //   Frame register ← recomputed from UNWIND_INFO
        if !target_ip.is_null() {
            // SAFETY: ctx is a valid, writable CONTEXT buffer.
            unsafe { ctx_write(ctx, CTX_RIP, target_ip as u64) };
        }
        // SAFETY: ctx is a valid, writable CONTEXT buffer.
        unsafe { ctx_write(ctx, CTX_RAX, return_value as u64) };

        // Fix up the frame register (typically RBP) for the target function.
        //
        // If the target function uses UWOP_SET_FPREG (e.g. "mov rbp, rsp" in
        // the prologue), the landing pad expects the frame register to hold
        // `establisher_frame + frame_offset * 16`.  Without this correction,
        // the frame register retains whatever stale value it had from the
        // Phase 1 walk, causing the landing pad to read from wrong memory.
        if !target_fe.is_null() && target_image_base != 0 && target_establisher != 0 {
            // SAFETY: target_fe and target_image_base are from the Phase 2 walk.
            if let Some((reg_off, val)) =
                unsafe { compute_body_frame_reg(target_image_base, target_fe, target_establisher) }
            {
                unsafe { ctx_write(ctx, reg_off, val) };
            }
        }

        // For GCC-style exceptions (_GCC_specific_handler), ExceptionInformation[3]
        // holds the type-selector index. _GCC_specific_handler sets this during Phase 1
        // and reads it back into ctx->Rdx when called with EXCEPTION_TARGET_UNWIND.
        //
        // For MSVC C++ exceptions (__CxxFrameHandler3), the catch funclet expects
        // RDX = EstablisherFrame (the target frame address) so it can reconstruct
        // the parent function's frame pointer and access local variables.
        if !exception_record.is_null() {
            let exc = exception_record.cast::<ExceptionRecord>();
            // SAFETY: caller guarantees exception_record is a valid ExceptionRecord.
            let code = unsafe { (*exc).exception_code };
            if code == STATUS_MSVC_CPP_EXCEPTION {
                // MSVC C++ exception: funclet needs RDX = EstablisherFrame.
                unsafe { ctx_write(ctx, CTX_RDX, target_frame_addr) };
            } else {
                // GCC exception: RDX = type-selector from ExceptionInformation[3].
                let selector = unsafe { (*exc).exception_information[3] };
                unsafe { ctx_write(ctx, CTX_RDX, selector as u64) };
            }
        }
    }

    // ── Step 4: Restore registers and jump to the landing pad ─────────────
    // SAFETY: ctx is a valid CONTEXT; seh_restore_context_and_jump never returns.
    unsafe { seh_restore_context_and_jump(ctx) };
}

/// Add vectored exception handler
///
/// Accepts the handler registration; returns a non-NULL handle to indicate
/// success.  Vectored handlers are not yet invoked by `RaiseException`.
///
/// # Safety
/// Safe to call with any arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_AddVectoredExceptionHandler(
    _first: u32,
    _handler: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // Return a fake handle (non-NULL) to indicate success
    0x1000 as *mut core::ffi::c_void
}

/// Remove a vectored exception handler previously added via
/// `AddVectoredExceptionHandler`.
///
/// Returns non-zero on success, 0 on failure.
///
/// # Safety
/// Safe to call with any non-NULL handle value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RemoveVectoredExceptionHandler(
    _handler: *mut core::ffi::c_void,
) -> u32 {
    // The stub in AddVectoredExceptionHandler returns a fake handle.
    // Removal always succeeds.
    1
}

//
// Phase 8.3: String Operations
//
// Windows uses UTF-16 (wide characters) while Linux uses UTF-8.
// These functions handle conversion between the two encodings.
//

/// Convert multibyte string to wide-character string
///
/// This implements MultiByteToWideChar for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `multi_byte_str`: Source multibyte string
/// - `multi_byte_len`: Length of source string (-1 = null-terminated)
/// - `wide_char_str`: Destination buffer for wide chars (NULL = query size)
/// - `wide_char_len`: Size of destination buffer in characters
///
/// # Returns
/// Number of wide characters written (or required if `wide_char_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `multi_byte_str` points to valid memory
/// - If `multi_byte_len` != -1, at least `multi_byte_len` bytes are readable
/// - If `wide_char_str` is not NULL, at least `wide_char_len` u16s are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MultiByteToWideChar(
    code_page: u32,
    _flags: u32,
    multi_byte_str: *const u8,
    multi_byte_len: i32,
    wide_char_str: *mut u16,
    wide_char_len: i32,
) -> i32 {
    if multi_byte_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate multi_byte_len (must be -1 or >= 0)
    if multi_byte_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if multi_byte_len == -1 {
        // SAFETY: Caller guarantees multi_byte_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *multi_byte_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (multi_byte_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees multi_byte_str points to at least input_len bytes
    let input_bytes = unsafe { core::slice::from_raw_parts(multi_byte_str, input_len) };

    // Convert to UTF-8 string (assume input is UTF-8)
    let Ok(utf8_str) = core::str::from_utf8(input_bytes) else {
        return 0; // Invalid UTF-8
    };

    // Convert to UTF-16
    let utf16_chars: Vec<u16> = utf8_str.encode_utf16().collect();
    let required_len = if include_null {
        utf16_chars.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf16_chars.len() // No null terminator when length was explicit
    };

    // If wide_char_str is NULL, return required size
    if wide_char_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if wide_char_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees wide_char_str has space for wide_char_len u16s
    let output = unsafe { core::slice::from_raw_parts_mut(wide_char_str, wide_char_len as usize) };

    // Copy the UTF-16 characters
    output[..utf16_chars.len()].copy_from_slice(&utf16_chars);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf16_chars.len()] = 0;
    }

    required_len as i32
}

/// Convert wide-character string to multibyte string
///
/// This implements WideCharToMultiByte for UTF-8 (CP_UTF8 = 65001) encoding.
///
/// # Arguments
/// - `code_page`: Character encoding (0 = CP_ACP, 65001 = CP_UTF8)
/// - `flags`: Conversion flags (0 = default)
/// - `wide_char_str`: Source wide-character string
/// - `wide_char_len`: Length of source string (-1 = null-terminated)
/// - `multi_byte_str`: Destination buffer for multibyte chars (NULL = query size)
/// - `multi_byte_len`: Size of destination buffer in bytes
/// - `default_char`: Default char for unmappable characters (NULL = use default)
/// - `used_default_char`: Pointer to flag set if default char was used (NULL = ignore)
///
/// # Returns
/// Number of bytes written (or required if `multi_byte_str` is NULL)
///
/// # Safety
/// The caller must ensure:
/// - `wide_char_str` points to valid memory
/// - If `wide_char_len` != -1, at least `wide_char_len` u16s are readable
/// - If `multi_byte_str` is not NULL, at least `multi_byte_len` bytes are writable
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WideCharToMultiByte(
    code_page: u32,
    _flags: u32,
    wide_char_str: *const u16,
    wide_char_len: i32,
    multi_byte_str: *mut u8,
    multi_byte_len: i32,
    _default_char: *const u8,
    _used_default_char: *mut i32,
) -> i32 {
    if wide_char_str.is_null() {
        return 0;
    }

    // Validate code page (only support CP_ACP=0 and CP_UTF8=65001)
    if code_page != CP_ACP && code_page != CP_UTF8 {
        return 0; // Unsupported code page
    }

    // Validate wide_char_len (must be -1 or >= 0)
    if wide_char_len < -1 {
        return 0; // Invalid parameter
    }

    // Determine the length of the input string
    let (input_len, include_null) = if wide_char_len == -1 {
        // SAFETY: Caller guarantees wide_char_str is a valid null-terminated string
        let mut len = 0;
        while unsafe { *wide_char_str.add(len) } != 0 {
            len += 1;
        }
        (len, true) // Include null terminator in output
    } else {
        (wide_char_len as usize, false) // Don't include null terminator
    };

    // SAFETY: Caller guarantees wide_char_str points to at least input_len u16s
    let input_chars = unsafe { core::slice::from_raw_parts(wide_char_str, input_len) };

    // Convert from UTF-16 to String (UTF-8)
    let utf8_string = String::from_utf16_lossy(input_chars);
    let utf8_bytes = utf8_string.as_bytes();
    let required_len = if include_null {
        utf8_bytes.len() + 1 // +1 for null terminator when input was null-terminated
    } else {
        utf8_bytes.len() // No null terminator when length was explicit
    };

    // If multi_byte_str is NULL, return required size
    if multi_byte_str.is_null() {
        return required_len as i32;
    }

    // Check buffer size
    if multi_byte_len < required_len as i32 {
        return 0; // Buffer too small
    }

    // SAFETY: Caller guarantees multi_byte_str has space for multi_byte_len bytes
    let output =
        unsafe { core::slice::from_raw_parts_mut(multi_byte_str, multi_byte_len as usize) };

    // Copy the UTF-8 bytes
    output[..utf8_bytes.len()].copy_from_slice(utf8_bytes);

    // Add null terminator only if input was null-terminated
    if include_null {
        output[utf8_bytes.len()] = 0;
    }

    required_len as i32
}

/// Get the length of a wide-character string
///
/// This implements lstrlenW, which returns the length of a null-terminated
/// wide-character string (excluding the null terminator).
///
/// # Safety
/// The caller must ensure `wide_str` points to a valid null-terminated wide string
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrlenW(wide_str: *const u16) -> i32 {
    if wide_str.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees wide_str is a valid null-terminated string
    let mut len = 0;
    while unsafe { *wide_str.add(len) } != 0 {
        len += 1;
    }

    len as i32
}

/// Compare two Unicode strings using ordinal (binary) comparison
///
/// This implements CompareStringOrdinal, which performs a code-point by code-point
/// comparison of two Unicode strings.
///
/// # Arguments
/// - `string1`: First string to compare
/// - `count1`: Length of first string (-1 = null-terminated)
/// - `string2`: Second string to compare
/// - `count2`: Length of second string (-1 = null-terminated)
/// - `ignore_case`: TRUE to ignore case, FALSE for case-sensitive
///
/// # Returns
/// - CSTR_LESS_THAN (1): string1 < string2
/// - CSTR_EQUAL (2): string1 == string2
/// - CSTR_GREATER_THAN (3): string1 > string2
/// - 0: Error
///
/// # Safety
/// The caller must ensure both string pointers point to valid memory
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CompareStringOrdinal(
    string1: *const u16,
    count1: i32,
    string2: *const u16,
    count2: i32,
    ignore_case: i32,
) -> i32 {
    if string1.is_null() || string2.is_null() {
        return 0; // Error
    }

    // Validate count1 and count2 (must be -1 or >= 0)
    if count1 < -1 || count2 < -1 {
        return 0; // Invalid parameter
    }

    // Get length of first string
    let len1 = if count1 == -1 {
        // SAFETY: Caller guarantees string1 is null-terminated
        let mut len = 0;
        while unsafe { *string1.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count1 as usize
    };

    // Get length of second string
    let len2 = if count2 == -1 {
        // SAFETY: Caller guarantees string2 is null-terminated
        let mut len = 0;
        while unsafe { *string2.add(len) } != 0 {
            len += 1;
        }
        len
    } else {
        count2 as usize
    };

    // SAFETY: Caller guarantees the pointers are valid
    let slice1 = unsafe { core::slice::from_raw_parts(string1, len1) };
    let slice2 = unsafe { core::slice::from_raw_parts(string2, len2) };

    // Perform ordinal (binary) comparison on UTF-16 code units
    // This matches Windows' ordinal semantics (code-unit by code-unit comparison)
    let min_len = core::cmp::min(len1, len2);
    let mut result = core::cmp::Ordering::Equal;

    for i in 0..min_len {
        let mut c1 = slice1[i];
        let mut c2 = slice2[i];

        if ignore_case != 0 {
            // ASCII case fold: 'A'..='Z' -> 'a'..='z'
            // This provides basic case-insensitive comparison for ASCII characters
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c1) {
                c1 += u16::from(b'a') - u16::from(b'A');
            }
            if (u16::from(b'A')..=u16::from(b'Z')).contains(&c2) {
                c2 += u16::from(b'a') - u16::from(b'A');
            }
        }

        if c1 < c2 {
            result = core::cmp::Ordering::Less;
            break;
        } else if c1 > c2 {
            result = core::cmp::Ordering::Greater;
            break;
        }
    }

    // If all compared code units are equal, shorter string is "less"
    if result == core::cmp::Ordering::Equal {
        result = len1.cmp(&len2);
    }

    // Convert to Windows constants
    match result {
        core::cmp::Ordering::Less => 1,    // CSTR_LESS_THAN
        core::cmp::Ordering::Equal => 2,   // CSTR_EQUAL
        core::cmp::Ordering::Greater => 3, // CSTR_GREATER_THAN
    }
}

//
// Phase 8.4: Performance Counters
//
// Windows programs often use high-resolution performance counters for timing.
// On Linux, we implement these using clock_gettime(CLOCK_MONOTONIC).
//

/// Windows FILETIME structure (64-bit value representing 100-nanosecond intervals since 1601-01-01)
#[repr(C)]
pub struct FileTime {
    low_date_time: u32,
    high_date_time: u32,
}

/// Query the performance counter
///
/// This implements QueryPerformanceCounter which returns a high-resolution timestamp.
/// On Linux, we use clock_gettime(CLOCK_MONOTONIC) which provides nanosecond precision.
///
/// # Safety
/// The caller must ensure `counter` points to a valid u64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceCounter(counter: *mut i64) -> i32 {
    if counter.is_null() {
        return 0; // FALSE - error
    }

    // SAFETY: Use libc to get monotonic time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        return 0; // FALSE - error
    }

    // Convert to a counter value (nanoseconds)
    let nanoseconds = ts
        .tv_sec
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec);

    // SAFETY: Caller guarantees counter is valid
    unsafe {
        *counter = nanoseconds;
    }

    1 // TRUE - success
}

/// Query the performance counter frequency
///
/// This implements QueryPerformanceFrequency which returns the frequency of the
/// performance counter in counts per second. Since we use nanoseconds, the frequency
/// is 1,000,000,000 (1 billion counts per second).
///
/// # Safety
/// The caller must ensure `frequency` points to a valid i64
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryPerformanceFrequency(frequency: *mut i64) -> i32 {
    if frequency.is_null() {
        return 0; // FALSE - error
    }

    // Our counter is in nanoseconds, so frequency is 1 billion counts/second
    // SAFETY: Caller guarantees frequency is valid
    unsafe {
        *frequency = 1_000_000_000;
    }

    1 // TRUE - success
}

/// Get system time as FILETIME with high precision
///
/// This implements GetSystemTimePreciseAsFileTime which returns the current system time
/// in FILETIME format (100-nanosecond intervals since January 1, 1601 UTC).
///
/// # Safety
/// The caller must ensure `filetime` points to a valid FILETIME structure
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemTimePreciseAsFileTime(filetime: *mut FileTime) {
    if filetime.is_null() {
        return;
    }

    // SAFETY: Use libc to get real time
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    // SAFETY: clock_gettime is safe to call
    let result = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, core::ptr::addr_of_mut!(ts)) };

    if result != 0 {
        // On error, return epoch
        unsafe {
            (*filetime).low_date_time = 0;
            (*filetime).high_date_time = 0;
        }
        return;
    }

    // Convert Unix timestamp (seconds since 1970-01-01) to Windows FILETIME
    // (100-nanosecond intervals since 1601-01-01)
    //
    // The difference between 1601-01-01 and 1970-01-01 is 11644473600 seconds

    // Convert to 100-nanosecond intervals
    let seconds_since_1601 = ts.tv_sec + EPOCH_DIFF;
    let intervals = seconds_since_1601
        .saturating_mul(10_000_000) // seconds to 100-nanosecond intervals
        .saturating_add(ts.tv_nsec / 100); // add nanoseconds converted to 100-ns intervals

    // Split into low and high parts
    // SAFETY: Caller guarantees filetime is valid
    unsafe {
        (*filetime).low_date_time = (intervals & 0xFFFF_FFFF) as u32;
        (*filetime).high_date_time = ((intervals >> 32) & 0xFFFF_FFFF) as u32;
    }
}

/// GetSystemTimeAsFileTime
///
/// Compatibility wrapper over `GetSystemTimePreciseAsFileTime`.
///
/// # Safety
/// `filetime` may be null; otherwise it must point to writable `FileTime`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemTimeAsFileTime(filetime: *mut FileTime) {
    unsafe { kernel32_GetSystemTimePreciseAsFileTime(filetime) };
}

//
// Phase 8.5: File I/O Trampolines
//
// These are KERNEL32 wrappers around file operations.
// They provide a Windows-compatible API but use simple stub implementations
// since full file I/O is handled through NTDLL APIs.
//

/// Create or open a file (CreateFileW)
///
/// Implements the most common creation dispositions and access modes.
/// File attributes and flags beyond `GENERIC_READ`/`GENERIC_WRITE` are ignored.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileW(
    file_name: *const u16,
    desired_access: u32,
    _share_mode: u32,
    _security_attributes: *mut core::ffi::c_void,
    creation_disposition: u32,
    _flags_and_attributes: u32,
    _template_file: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = usize::MAX as *mut core::ffi::c_void;

    // Windows GENERIC_READ / GENERIC_WRITE flags
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;

    // CreationDisposition constants
    const CREATE_NEW: u32 = 1;
    const CREATE_ALWAYS: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const OPEN_ALWAYS: u32 = 4;
    const TRUNCATE_EXISTING: u32 = 5;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE_VALUE;
    }

    let path_str = wide_path_to_linux(file_name);
    let can_read = desired_access & GENERIC_READ != 0;
    let can_write = desired_access & GENERIC_WRITE != 0;
    // When desired_access=0 (Windows attribute/metadata query), neither read nor write
    // is requested.  Linux requires at least one access mode; open read-only so that
    // fstat and similar metadata operations work.
    let need_read = can_read || !can_write;

    let result = match creation_disposition {
        CREATE_NEW => std::fs::OpenOptions::new()
            .read(need_read)
            .write(can_write)
            .create_new(true)
            .open(&path_str),
        CREATE_ALWAYS => std::fs::OpenOptions::new()
            .read(need_read)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path_str),
        OPEN_EXISTING => std::fs::OpenOptions::new()
            .read(need_read)
            .write(can_write)
            .open(&path_str),
        OPEN_ALWAYS => std::fs::OpenOptions::new()
            .read(need_read)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path_str),
        TRUNCATE_EXISTING => std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path_str),
        _ => {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return INVALID_HANDLE_VALUE;
        }
    };

    match result {
        Ok(file) => {
            // Enforce the open-handle limit atomically inside the mutex so
            // that the check and insert cannot race with other threads.
            let handle_val = alloc_file_handle();
            let inserted = with_file_handles(|map| {
                if map.len() >= MAX_OPEN_FILE_HANDLES {
                    return false;
                }
                map.insert(handle_val, FileEntry::new(file));
                true
            });
            if inserted {
                handle_val as *mut core::ffi::c_void
            } else {
                kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
                INVALID_HANDLE_VALUE
            }
        }
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::AlreadyExists => 80, // ERROR_FILE_EXISTS
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::NotFound => 2,       // ERROR_FILE_NOT_FOUND
                _ => 87,                                 // ERROR_INVALID_PARAMETER
            };
            kernel32_SetLastError(code);
            INVALID_HANDLE_VALUE
        }
    }
}

/// CreateFileA - creates or opens a file (ANSI version)
///
/// Converts the narrow-character file name to UTF-16 and delegates to
/// `kernel32_CreateFileW`.
///
/// # Safety
/// `file_name` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileA(
    file_name: *const u8,
    desired_access: u32,
    share_mode: u32,
    security_attributes: *mut core::ffi::c_void,
    creation_disposition: u32,
    flags_and_attributes: u32,
    template_file: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = usize::MAX as *mut core::ffi::c_void;
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE_VALUE;
    }
    let path = std::ffi::CStr::from_ptr(file_name.cast::<i8>()).to_string_lossy();
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    kernel32_CreateFileW(
        wide.as_ptr(),
        desired_access,
        share_mode,
        security_attributes,
        creation_disposition,
        flags_and_attributes,
        template_file,
    )
}

/// Read from a file (ReadFile)
///
/// When `overlapped` is non-null and the file handle is associated with an
/// I/O Completion Port, the completion packet is posted to that port after
/// a successful synchronous read.
///
/// # Safety
/// `file` must be a valid handle, `buffer` must be writable for
/// `number_of_bytes_to_read` bytes, and `number_of_bytes_read` must be
/// a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFile(
    file: *mut core::ffi::c_void,
    buffer: *mut u8,
    number_of_bytes_to_read: u32,
    number_of_bytes_read: *mut u32,
    overlapped: *mut core::ffi::c_void,
) -> i32 {
    if buffer.is_null() {
        kernel32_SetLastError(87);
        return 0;
    }

    let handle_val = file as usize;
    let count = number_of_bytes_to_read as usize;
    // SAFETY: Caller guarantees buffer is valid for `count` bytes.
    let slice = std::slice::from_raw_parts_mut(buffer, count);

    // Read and capture IOCP association in one lock.
    let result = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            let n = entry.file.read(slice).ok();
            let iocp = entry.iocp_handle;
            let key = entry.completion_key;
            (n, iocp, key)
        } else {
            (None, 0, 0)
        }
    });

    let (bytes_opt, iocp_handle, completion_key) = result;
    if let Some(n) = bytes_opt {
        let bytes = u32::try_from(n).unwrap_or(u32::MAX);
        if !number_of_bytes_read.is_null() {
            *number_of_bytes_read = bytes;
        }
        // If the file is IOCP-associated and an OVERLAPPED was provided,
        // post the completion to the port and mark the result in OVERLAPPED.
        if !overlapped.is_null() && iocp_handle != 0 {
            set_overlapped_result(overlapped, 0, u64::from(bytes));
            post_iocp_completion(iocp_handle, bytes, completion_key, overlapped as usize, 0);
        }
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        if !number_of_bytes_read.is_null() {
            *number_of_bytes_read = 0;
        }
        0 // FALSE
    }
}

/// Write to a file (WriteFile)
///
/// Writes to stdout/stderr or to a regular file opened by `CreateFileW`.
/// When `overlapped` is non-null and the file handle is associated with an
/// I/O Completion Port, the completion packet is posted to that port after
/// a successful synchronous write.
///
/// # Safety
/// This function is unsafe as it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFile(
    file: *mut core::ffi::c_void,
    buffer: *const u8,
    number_of_bytes_to_write: u32,
    number_of_bytes_written: *mut u32,
    overlapped: *mut core::ffi::c_void,
) -> i32 {
    // STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    let stdout_handle = kernel32_GetStdHandle((-11i32) as u32);
    let stderr_handle = kernel32_GetStdHandle((-12i32) as u32);

    // Check if this is stdout or stderr
    let is_stdout = file == stdout_handle;
    let is_stderr = file == stderr_handle;

    if buffer.is_null() || number_of_bytes_to_write == 0 {
        if !number_of_bytes_written.is_null() {
            *number_of_bytes_written = 0;
        }
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // SAFETY: Caller guarantees buffer is valid for number_of_bytes_to_write bytes
    let data = std::slice::from_raw_parts(buffer, number_of_bytes_to_write as usize);

    if is_stdout || is_stderr {
        // Write to stdout or stderr
        let result = if is_stdout {
            std::io::Write::write(&mut std::io::stdout(), data)
        } else {
            std::io::Write::write(&mut std::io::stderr(), data)
        };
        if let Ok(written) = result {
            if !number_of_bytes_written.is_null() {
                // Windows API uses u32 for byte counts; saturate rather than truncate.
                *number_of_bytes_written = u32::try_from(written).unwrap_or(u32::MAX);
            }
            if is_stdout {
                let _ = std::io::Write::flush(&mut std::io::stdout());
            } else {
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
            1 // TRUE
        } else {
            kernel32_SetLastError(29); // ERROR_WRITE_FAULT
            0
        }
    } else {
        // Try regular file handle
        let handle_val = file as usize;
        let result = with_file_handles(|map| {
            if let Some(entry) = map.get_mut(&handle_val) {
                let n = entry.file.write(data).ok();
                let iocp = entry.iocp_handle;
                let key = entry.completion_key;
                (n, iocp, key)
            } else {
                (None, 0, 0)
            }
        });
        let (bytes_opt, iocp_handle, completion_key) = result;
        if let Some(n) = bytes_opt {
            let bytes = u32::try_from(n).unwrap_or(u32::MAX);
            if !number_of_bytes_written.is_null() {
                *number_of_bytes_written = bytes;
            }
            if !overlapped.is_null() && iocp_handle != 0 {
                set_overlapped_result(overlapped, 0, u64::from(bytes));
                post_iocp_completion(iocp_handle, bytes, completion_key, overlapped as usize, 0);
            }
            1 // TRUE
        } else {
            kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
            if !number_of_bytes_written.is_null() {
                *number_of_bytes_written = 0;
            }
            0 // FALSE
        }
    }
}

/// Close a handle (CloseHandle)
///
/// Closes file handles opened by `CreateFileW` and event handles opened by
/// `CreateEventW`. Directory-search handles opened by `FindFirstFileW` /
/// `FindNextFileW` must be closed using `FindClose`, not `CloseHandle`.
/// Thread handles and process handles returned by `CreateProcessW` are also
/// accepted.
///
/// # Safety
/// This function is safe to call with any argument.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CloseHandle(handle: *mut core::ffi::c_void) -> i32 {
    let handle_val = handle as usize;
    // Remove from file-handle map if present (this closes the underlying File)
    with_file_handles(|map| {
        map.remove(&handle_val);
    });
    // Remove from event-handle map if present (drops the Arc-backed event state)
    with_event_handles(|map| {
        map.remove(&handle_val);
    });
    // Remove from sync-handle map if present (drops the Arc-backed sync state)
    with_sync_handles(|map| {
        map.remove(&handle_val);
    });
    // Remove from process-handle map if present (allows the child to be cleaned up)
    with_process_handles(|map| {
        map.remove(&handle_val);
    });
    1 // TRUE - success (or was not a registered handle)
}

//
// Phase 8.6: Heap Management Trampolines
//
// Windows programs often use HeapAlloc/HeapFree for dynamic memory.
// These are wrappers around the standard malloc/free functions.
//

/// Get the default process heap handle
///
/// In Windows, processes have a default heap. We return a fake
/// non-NULL handle since programs check for NULL.
///
/// # Safety
/// This function is safe to call. It returns a constant non-NULL value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessHeap() -> *mut core::ffi::c_void {
    // Return a fake heap handle (non-NULL)
    // Real heap operations use malloc/free directly
    0x1000 as *mut core::ffi::c_void
}

/// Allocate memory from a heap
///
/// This wraps malloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored, we use the global allocator)
/// - `flags`: Allocation flags (HEAP_ZERO_MEMORY = 0x00000008)
/// - `size`: Number of bytes to allocate
///
/// # Returns
/// Pointer to allocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The returned pointer must be freed with HeapFree.
/// The caller must ensure the size is reasonable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapAlloc(
    _heap: *mut core::ffi::c_void,
    flags: u32,
    size: usize,
) -> *mut core::ffi::c_void {
    // Windows HeapAlloc can return a non-NULL pointer for 0-byte allocation
    // Allocate a minimal block (1 byte) to match Windows semantics
    let alloc_size = if size == 0 { 1 } else { size };

    // Allocate using the global allocator
    let Ok(layout) =
        core::alloc::Layout::from_size_align(alloc_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    // SAFETY: Layout is valid, size is non-zero
    let ptr = unsafe { alloc::alloc(layout) };

    if ptr.is_null() {
        return core::ptr::null_mut();
    }

    // Zero memory if requested
    if flags & HEAP_ZERO_MEMORY != 0 {
        // SAFETY: ptr is valid and has alloc_size bytes allocated
        unsafe {
            core::ptr::write_bytes(ptr, 0, alloc_size);
        }
    }

    // Track this allocation for later deallocation
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    if let Some(ref mut t) = *tracker {
        t.track_allocation(ptr, alloc_size, layout.align());
    }

    ptr.cast()
}

/// Free memory allocated from a heap
///
/// This wraps dealloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Free flags (ignored)
/// - `mem`: Pointer to memory to free
///
/// # Returns
/// TRUE (1) on success, FALSE (0) on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - `mem` is not freed twice
/// - `mem` is not used after being freed
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapFree(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *mut core::ffi::c_void,
) -> i32 {
    if mem.is_null() {
        return 1; // TRUE - freeing NULL is a no-op
    }

    // Retrieve and remove the allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        // If tracker doesn't exist, we can't free safely
        return 0; // FALSE - failure
    };

    let Some((size, align)) = t.remove_allocation(mem) else {
        // Allocation not found - this is either a double-free or
        // memory not allocated with HeapAlloc
        return 0; // FALSE - failure
    };

    // Create the layout and deallocate
    // SAFETY: We're recreating the same layout that was used for allocation
    let Ok(layout) = core::alloc::Layout::from_size_align(size, align) else {
        return 0; // FALSE - invalid layout (shouldn't happen)
    };

    // SAFETY: ptr was allocated with alloc::alloc using this layout
    unsafe {
        alloc::dealloc(mem.cast(), layout);
    }

    1 // TRUE - success
}

/// Reallocate memory in a heap
///
/// This wraps realloc to provide Windows heap semantics.
///
/// # Arguments
/// - `heap`: Heap handle (ignored)
/// - `flags`: Realloc flags (HEAP_ZERO_MEMORY supported)
/// - `mem`: Pointer to memory to reallocate (or NULL to allocate new)
/// - `size`: New size in bytes
///
/// # Returns
/// Pointer to reallocated memory, or NULL on failure
///
/// # Panics
/// Panics if the heap tracker mutex is poisoned (another thread panicked while holding the lock).
///
/// # Safety
/// The caller must ensure:
/// - `mem` was allocated with HeapAlloc or is NULL
/// - The old pointer is not used after reallocation
/// - The returned pointer must be freed with HeapFree
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapReAlloc(
    heap: *mut core::ffi::c_void,
    flags: u32,
    mem: *mut core::ffi::c_void,
    size: usize,
) -> *mut core::ffi::c_void {
    if mem.is_null() {
        // Allocate new memory
        return unsafe { kernel32_HeapAlloc(heap, flags, size) };
    }

    if size == 0 {
        // Free the memory
        unsafe { kernel32_HeapFree(heap, flags, mem) };
        return core::ptr::null_mut();
    }

    // Get the current allocation info
    ensure_heap_tracker_initialized();
    let mut tracker = HEAP_TRACKER.lock().unwrap();
    let Some(ref mut t) = *tracker else {
        return core::ptr::null_mut(); // Tracker not initialized
    };

    let Some((old_size, old_align)) = t.get_allocation(mem) else {
        // Memory not tracked - can't reallocate safely
        return core::ptr::null_mut();
    };

    // Prepare new allocation
    let new_size = if size == 0 { 1 } else { size };
    let Ok(new_layout) =
        core::alloc::Layout::from_size_align(new_size, core::mem::align_of::<usize>())
    else {
        return core::ptr::null_mut();
    };

    let Ok(old_layout) = core::alloc::Layout::from_size_align(old_size, old_align) else {
        return core::ptr::null_mut();
    };

    // Remove the old allocation entry BEFORE realloc, since realloc may move the memory
    t.remove_allocation(mem);

    // SAFETY: mem was allocated with the old_layout
    let new_ptr = unsafe { alloc::realloc(mem.cast(), old_layout, new_size) };

    if new_ptr.is_null() {
        // Realloc failed - the original allocation is still valid
        // Re-insert the original allocation back into the tracker
        t.track_allocation(mem.cast(), old_size, old_align);
        return core::ptr::null_mut();
    }

    // If growing the allocation and HEAP_ZERO_MEMORY is set, zero the new bytes
    if new_size > old_size && (flags & HEAP_ZERO_MEMORY != 0) {
        // SAFETY: new_ptr is valid for new_size bytes, and we're only writing
        // to the newly allocated portion
        unsafe {
            core::ptr::write_bytes(new_ptr.add(old_size), 0, new_size - old_size);
        }
    }

    // Track the new allocation (whether it moved or stayed in place)
    t.track_allocation(new_ptr, new_size, new_layout.align());

    new_ptr.cast()
}

/// STARTUPINFOA structure - contains information about window station, desktop, standard handles, etc.
/// This is a simplified version that matches the Windows API layout.
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoA {
    cb: u32,
    lpReserved: *mut u8,
    lpDesktop: *mut u8,
    lpTitle: *mut u8,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// STARTUPINFOW structure - wide-character version
#[repr(C)]
#[allow(non_snake_case)]
struct StartupInfoW {
    cb: u32,
    lpReserved: *mut u16,
    lpDesktop: *mut u16,
    lpTitle: *mut u16,
    dwX: u32,
    dwY: u32,
    dwXSize: u32,
    dwYSize: u32,
    dwXCountChars: u32,
    dwYCountChars: u32,
    dwFillAttribute: u32,
    dwFlags: u32,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: *mut u8,
    hStdInput: usize,
    hStdOutput: usize,
    hStdError: usize,
}

/// GetStartupInfoA - retrieves the STARTUPINFO structure for the current process
///
/// This is a minimal implementation that sets the structure to default values.
/// In a real Windows environment, this would contain information passed to CreateProcess.
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOA structure
/// - The pointer is properly aligned for a STARTUPINFOA structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoA(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoA structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoA>()) };

    // Initialize the structure with default values
    // In a real implementation, these would come from the process's startup information
    info.cb = core::mem::size_of::<StartupInfoA>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0; // Could be mapped to actual stdin fd
    info.hStdOutput = 1; // Could be mapped to actual stdout fd
    info.hStdError = 2; // Could be mapped to actual stderr fd
}

/// GetStartupInfoW - retrieves the STARTUPINFOW structure for the current process (wide-char version)
///
/// # Safety
/// The caller must ensure:
/// - `startup_info` points to a valid writable STARTUPINFOW structure
/// - The pointer is properly aligned for a STARTUPINFOW structure (8-byte alignment)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStartupInfoW(startup_info: *mut u8) {
    if startup_info.is_null() {
        return;
    }

    // SAFETY: Caller guarantees startup_info points to valid writable memory
    // with proper alignment for StartupInfoW structure (8-byte alignment required).
    // The cast_ptr_alignment lint is allowed because the alignment requirement
    // is documented in the function's safety contract.
    #[allow(clippy::cast_ptr_alignment)]
    let info = unsafe { &mut *(startup_info.cast::<StartupInfoW>()) };

    // Initialize the structure with default values
    info.cb = core::mem::size_of::<StartupInfoW>() as u32;
    info.lpReserved = core::ptr::null_mut();
    info.lpDesktop = core::ptr::null_mut();
    info.lpTitle = core::ptr::null_mut();
    info.dwX = 0;
    info.dwY = 0;
    info.dwXSize = 0;
    info.dwYSize = 0;
    info.dwXCountChars = 0;
    info.dwYCountChars = 0;
    info.dwFillAttribute = 0;
    info.dwFlags = 0;
    info.wShowWindow = 1; // SW_SHOWNORMAL
    info.cbReserved2 = 0;
    info.lpReserved2 = core::ptr::null_mut();
    // Standard handles - use placeholder values
    info.hStdInput = 0;
    info.hStdOutput = 1;
    info.hStdError = 2;
}

//
// Stub implementations for missing APIs
//
// These are minimal implementations that return failure or no-op.
// They allow programs to link and run, but don't provide full functionality.
//

/// CancelIo - cancels all pending input and output (I/O) operations
///
/// All I/O in this implementation is synchronous, so there are no pending
/// operations to cancel.  Returns TRUE to indicate success.
///
/// # Safety
/// This function never dereferences any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CancelIo(_file: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - no pending I/O to cancel
}

/// CopyFileExW - copies a file (progress callback and cancel flag are ignored)
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CopyFileExW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    _progress_routine: *mut core::ffi::c_void,
    _data: *mut core::ffi::c_void,
    _cancel: *mut i32,
    _copy_flags: u32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    match std::fs::copy(&src, &dst) {
        Ok(_) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 1,                                    // ERROR_INVALID_FUNCTION
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CopyFileW - copies a file
///
/// Simplified wrapper around `CopyFileExW` (no progress callback, no cancel).
///
/// Note: when `fail_if_exists` is non-zero, there is a TOCTOU window between
/// the existence check and the copy. In the sandboxed single-process context
/// this is typically harmless, but callers should be aware of the limitation.
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CopyFileW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    fail_if_exists: i32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    if fail_if_exists != 0 && std::path::Path::new(&dst).exists() {
        kernel32_SetLastError(183); // ERROR_ALREADY_EXISTS
        return 0;
    }
    match std::fs::copy(&src, &dst) {
        Ok(_) => 1,
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,
                std::io::ErrorKind::PermissionDenied => 5,
                _ => 1,
            };
            kernel32_SetLastError(code);
            0
        }
    }
}

/// CreateDirectoryW - creates a directory
///
/// Creates the directory named by `path_name`.  Security attributes are ignored.
///
/// # Safety
/// `path_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateDirectoryW(
    path_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(path_name);
    match std::fs::create_dir(std::path::Path::new(&path_str)) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::AlreadyExists => 183, // ERROR_ALREADY_EXISTS
                std::io::ErrorKind::NotFound => 3,        // ERROR_PATH_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,                                   // ERROR_FILE_NOT_FOUND
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CreateDirectoryExW - creates a directory, ignoring the template directory argument.
///
/// Template directory attributes are not applied; this behaves like `CreateDirectoryW`.
///
/// # Safety
/// `new_directory` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateDirectoryExW(
    _template_directory: *const u16,
    new_directory: *const u16,
    security_attributes: *mut core::ffi::c_void,
) -> i32 {
    kernel32_CreateDirectoryW(new_directory, security_attributes)
}

/// CreateEventW - creates an event object
///
/// Creates a named or unnamed event object backed by a `Condvar` that can be
/// signaled with `SetEvent` and waited on with `WaitForSingleObject`.
///
/// `manual_reset` (non-zero) means the event stays signaled until explicitly
/// reset with `ResetEvent`; zero means the event auto-resets after one
/// waiter is released.  `initial_state` (non-zero) starts the event already
/// signaled.  Named events (`name` non-null) are currently treated as
/// anonymous; a unique synthetic handle is still returned.
///
/// This implementation always returns a non-null synthetic handle and does
/// not currently report allocation failures via `GetLastError()`.
///
/// # Safety
/// If `name` is non-null it must be a valid null-terminated UTF-16 string
/// (it is accepted but ignored).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateEventW(
    _security_attributes: *mut core::ffi::c_void,
    manual_reset: i32,
    initial_state: i32,
    _name: *const u16,
) -> *mut core::ffi::c_void {
    let handle = alloc_event_handle();
    let entry = EventEntry {
        manual_reset: manual_reset != 0,
        state: Arc::new((Mutex::new(initial_state != 0), Condvar::new())),
    };
    with_event_handles(|map| map.insert(handle, entry));
    handle as *mut core::ffi::c_void
}

/// CreateFileMappingA - creates or opens a named or unnamed file mapping object
///
/// `file` may be `INVALID_HANDLE_VALUE` (-1 as usize) for a pagefile-backed
/// (anonymous) mapping.  The `name` parameter (named mappings) is accepted
/// but ignored; all mappings are process-private.
///
/// # Safety
/// `file` must be a handle previously returned by `CreateFileW` (or
/// `INVALID_HANDLE_VALUE`).  `name`, if non-null, must be a valid
/// null-terminated ASCII string (not dereferenced here).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateFileMappingA(
    file: *mut core::ffi::c_void,
    _security_attributes: *mut core::ffi::c_void,
    protect: u32,
    maximum_size_high: u32,
    maximum_size_low: u32,
    _name: *const u8,
) -> *mut core::ffi::c_void {
    let handle_val = file as usize;
    let size = (u64::from(maximum_size_high) << 32) | u64::from(maximum_size_low);

    // INVALID_HANDLE_VALUE (usize::MAX, i.e. -1 cast to usize) means a
    // pagefile-backed anonymous mapping.
    let raw_fd = if handle_val == usize::MAX {
        -1i32
    } else {
        let fd = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.as_raw_fd()));
        let Some(fd) = fd else {
            kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
            return core::ptr::null_mut();
        };
        fd
    };

    let mapping_handle = alloc_file_mapping_handle();
    with_file_mapping_handles(|map| {
        map.insert(
            mapping_handle,
            FileMappingEntry {
                raw_fd,
                size,
                protect,
            },
        );
    });
    mapping_handle as *mut core::ffi::c_void
}

/// CreateHardLinkW - creates a hard link to an existing file
///
/// Creates a hard link at `file_name` pointing to `existing_file_name`.
/// Security attributes are ignored.
///
/// # Safety
/// `file_name` and `existing_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateHardLinkW(
    file_name: *const u16,
    existing_file_name: *const u16,
    _security_attributes: *mut core::ffi::c_void,
) -> i32 {
    if file_name.is_null() || existing_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let new_path = wide_path_to_linux(file_name);
    let existing_path = wide_path_to_linux(existing_file_name);
    match std::fs::hard_link(&existing_path, &new_path) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 1,                                    // ERROR_INVALID_FUNCTION
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CreatePipe - creates an anonymous pipe
///
/// Creates a unidirectional pipe; `read_pipe` receives the read-end handle
/// and `write_pipe` receives the write-end handle.  Both handles are
/// registered in the file-handle table so `ReadFile`/`WriteFile`/`CloseHandle`
/// work on them normally.  `pipe_attributes` (security/inheritability) and
/// `size` (suggested buffer size hint) are accepted but ignored.
///
/// # Safety
/// `read_pipe` and `write_pipe` must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreatePipe(
    read_pipe: *mut *mut core::ffi::c_void,
    write_pipe: *mut *mut core::ffi::c_void,
    _pipe_attributes: *mut core::ffi::c_void,
    _size: u32,
) -> i32 {
    if read_pipe.is_null() || write_pipe.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let mut pipe_fds = [0i32; 2];
    // SAFETY: pipe_fds is a valid two-element array for the pipe() syscall.
    if libc::pipe(pipe_fds.as_mut_ptr()) != 0 {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE (generic I/O error)
        return 0;
    }

    // SAFETY: pipe() returned valid, owned file descriptors.
    let read_file = File::from_raw_fd(pipe_fds[0]);
    let write_file = File::from_raw_fd(pipe_fds[1]);

    let read_handle = alloc_file_handle();
    let write_handle = alloc_file_handle();

    let inserted = with_file_handles(|map| {
        if map.len() + 2 > MAX_OPEN_FILE_HANDLES {
            return false;
        }
        map.insert(read_handle, FileEntry::new(read_file));
        map.insert(write_handle, FileEntry::new(write_file));
        true
    });

    if !inserted {
        kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return 0;
    }

    *read_pipe = read_handle as *mut core::ffi::c_void;
    *write_pipe = write_handle as *mut core::ffi::c_void;
    1 // TRUE
}

/// Windows `PROCESS_INFORMATION` layout (x64):
///   offset 0:  hProcess    (8 bytes)
///   offset 8:  hThread     (8 bytes)
///   offset 16: dwProcessId (4 bytes)
///   offset 20: dwThreadId  (4 bytes)
#[repr(C)]
struct ProcessInformation {
    h_process: usize,
    h_thread: usize,
    dw_process_id: u32,
    dw_thread_id: u32,
}

/// Parse a wide-char Windows command line into a program path and argument list.
///
/// Handles double-quoted tokens and backslash escaping per the Windows
/// `CommandLineToArgvW` rules.
///
/// # Safety
/// `cmd_line` must be a valid null-terminated UTF-16 string.
unsafe fn parse_command_line_wide(cmd_line: *const u16) -> Vec<String> {
    if cmd_line.is_null() {
        return Vec::new();
    }
    let s = wide_str_to_string(cmd_line);
    parse_command_line_str(&s)
}

/// Split a UTF-8 Windows command-line string into tokens.
fn parse_command_line_str(s: &str) -> Vec<String> {
    let mut args: Vec<String> = Vec::new();
    let mut chars = s.chars().peekable();
    loop {
        // skip whitespace between tokens
        while chars.peek() == Some(&' ') || chars.peek() == Some(&'\t') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut token = String::new();
        let mut in_quotes = false;
        loop {
            match chars.peek().copied() {
                None => break,
                Some('"') => {
                    chars.next();
                    in_quotes = !in_quotes;
                }
                Some(' ' | '\t') if !in_quotes => break,
                Some('\\') => {
                    chars.next();
                    // Count consecutive backslashes
                    let mut bs_count = 1;
                    while chars.peek() == Some(&'\\') {
                        chars.next();
                        bs_count += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        // Pairs of backslashes before a quote: each pair → one backslash
                        token.extend(std::iter::repeat_n('\\', bs_count / 2));
                        if bs_count % 2 == 1 {
                            // Odd number: the last backslash escapes the quote
                            chars.next();
                            token.push('"');
                        }
                    } else {
                        // No following quote: backslashes are literal
                        token.extend(std::iter::repeat_n('\\', bs_count));
                    }
                }
                Some(c) => {
                    chars.next();
                    token.push(c);
                }
            }
        }
        if !token.is_empty() {
            args.push(token);
        }
    }
    args
}

/// Convert a Windows path string to a Linux path (drive letter strip + separator swap).
fn win_path_to_linux_str(path: &str) -> String {
    let without_drive = if path.len() >= 2 && path.as_bytes()[1] == b':' {
        &path[2..]
    } else {
        path
    };
    let with_slashes = without_drive.replace('\\', "/");
    if with_slashes.is_empty() || !with_slashes.starts_with('/') {
        format!("/{with_slashes}")
    } else {
        with_slashes
    }
}

/// Read a null-terminated ANSI byte string pointer into a `String`, then encode it
/// as a null-terminated UTF-16 `Vec<u16>`.
///
/// # Safety
/// `ptr` must be null-terminated and readable.
unsafe fn ansi_ptr_to_wide_vec(ptr: *const u8) -> Vec<u16> {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let s = std::str::from_utf8(std::slice::from_raw_parts(ptr, len)).unwrap_or("");
    let mut w: Vec<u16> = s.encode_utf16().collect();
    w.push(0);
    w
}

/// CreateProcessW - creates a new process and its primary thread.
///
/// Spawns a child process.  When `application_name` ends with `.exe` (case-insensitive)
/// the LiteBox runner (current executable) is invoked with the `.exe` path so the
/// child Windows program runs under the emulation layer.  Otherwise the executable
/// is spawned directly as a native Linux binary.
///
/// `process_information` must point to a writable `PROCESS_INFORMATION` structure (24 bytes).
///
/// # Safety
/// - `application_name`, if non-null, must be a valid null-terminated UTF-16 string.
/// - `command_line`, if non-null, must be a valid null-terminated UTF-16 string.
/// - `current_directory`, if non-null, must be a valid null-terminated UTF-16 string.
/// - `process_information`, if non-null, must point to a writable 24-byte aligned region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateProcessW(
    application_name: *const u16,
    command_line: *mut u16,
    _process_attributes: *mut core::ffi::c_void,
    _thread_attributes: *mut core::ffi::c_void,
    _inherit_handles: i32,
    _creation_flags: u32,
    _environment: *mut core::ffi::c_void,
    current_directory: *const u16,
    _startup_info: *mut core::ffi::c_void,
    process_information: *mut core::ffi::c_void,
) -> i32 {
    // Determine the executable and argument list.
    // Windows rules:
    //   - If application_name is given it is the executable (no shell expansion).
    //   - command_line is the full command line (argv[0] + args); if application_name
    //     is also given, command_line[0] is treated as argv[0] but application_name
    //     is the actual binary to load.
    let (exe_str, args): (String, Vec<String>) = if !application_name.is_null() {
        let app = wide_str_to_string(application_name);
        let mut cmd_args = if command_line.is_null() {
            Vec::new()
        } else {
            // SAFETY: command_line is non-null and caller-guaranteed valid UTF-16.
            let tokens = parse_command_line_wide(command_line.cast_const());
            // Skip the program name token (argv[0]) from command_line
            if tokens.len() > 1 {
                tokens[1..].to_vec()
            } else {
                Vec::new()
            }
        };
        // Insert application_name as argv[0]
        cmd_args.insert(0, app.clone());
        (app, cmd_args)
    } else if !command_line.is_null() {
        // SAFETY: command_line is non-null and caller-guaranteed valid UTF-16.
        let tokens = parse_command_line_wide(command_line.cast_const());
        if tokens.is_empty() {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let exe = tokens[0].clone();
        (exe, tokens)
    } else {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    };

    // Convert Windows path to Linux path.
    let linux_exe = win_path_to_linux_str(&exe_str);

    // Determine whether this is a Windows PE (.exe) that needs the LiteBox runner,
    // or a native Linux binary that can be spawned directly.
    let is_windows_exe = linux_exe.to_ascii_lowercase().ends_with(".exe");

    // Build the Command.
    let mut cmd = if is_windows_exe {
        // Re-invoke the current LiteBox runner binary with the .exe as its first argument.
        let runner =
            std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("litebox"));
        let mut c = std::process::Command::new(runner);
        c.arg(&linux_exe);
        // Append remaining args (skip argv[0] which is the exe path)
        for arg in args.iter().skip(1) {
            c.arg(arg);
        }
        c
    } else {
        // Native Linux binary: pass args directly.
        let mut c = std::process::Command::new(&linux_exe);
        for arg in args.iter().skip(1) {
            c.arg(arg);
        }
        c
    };

    // Set working directory if provided.
    if !current_directory.is_null() {
        let cwd_wide = wide_str_to_string(current_directory);
        let cwd_linux = win_path_to_linux_str(&cwd_wide);
        cmd.current_dir(&cwd_linux);
    }

    // Spawn the child.
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,                                    // ERROR_FILE_NOT_FOUND
            };
            kernel32_SetLastError(code);
            return 0; // FALSE
        }
    };

    let pid = child.id();
    let child_arc: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(Some(child)));
    let exit_code_arc: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));

    // Allocate a synthetic process handle.
    let proc_handle = alloc_process_handle();

    // Allocate a fake thread handle (we don't track child threads individually).
    let thread_handle = alloc_process_handle();

    with_process_handles(|map| {
        map.insert(
            proc_handle,
            ProcessEntry {
                child: Arc::clone(&child_arc),
                pid,
                exit_code: Arc::clone(&exit_code_arc),
                is_process: true,
            },
        );
        // Insert a dummy entry for the fake thread handle so CloseHandle works.
        map.insert(
            thread_handle,
            ProcessEntry {
                child: Arc::new(Mutex::new(None)),
                pid,
                exit_code: Arc::new(Mutex::new(Some(0))),
                is_process: false,
            },
        );
    });

    // Fill PROCESS_INFORMATION if the caller supplied a pointer.
    if !process_information.is_null() {
        // SAFETY: caller guarantees process_information points to a valid writable
        // PROCESS_INFORMATION structure (24 bytes).
        let pi = process_information.cast::<ProcessInformation>();
        core::ptr::write_unaligned(
            pi,
            ProcessInformation {
                h_process: proc_handle,
                h_thread: thread_handle,
                dw_process_id: pid,
                dw_thread_id: 1,
            },
        );
    }

    1 // TRUE
}

/// CreateProcessA - ANSI variant of `CreateProcessW`.
///
/// Converts `application_name` and `command_line` from ANSI (Latin-1) to UTF-16
/// then delegates to `kernel32_CreateProcessW`.
///
/// # Safety
/// - `application_name`, if non-null, must be a valid null-terminated ANSI string.
/// - `command_line`, if non-null, must be a valid null-terminated ANSI string.
/// - `current_directory`, if non-null, must be a valid null-terminated ANSI string.
/// - `process_information`, if non-null, must point to a writable 24-byte aligned region.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateProcessA(
    application_name: *const u8,
    command_line: *mut u8,
    process_attributes: *mut core::ffi::c_void,
    thread_attributes: *mut core::ffi::c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *mut core::ffi::c_void,
    current_directory: *const u8,
    startup_info: *mut core::ffi::c_void,
    process_information: *mut core::ffi::c_void,
) -> i32 {
    // Convert ANSI strings to UTF-16 using the shared helper.
    let app_wide: Option<Vec<u16>> = if application_name.is_null() {
        None
    } else {
        Some(ansi_ptr_to_wide_vec(application_name))
    };
    let cmd_wide: Option<Vec<u16>> = if command_line.is_null() {
        None
    } else {
        Some(ansi_ptr_to_wide_vec(command_line))
    };
    let dir_wide: Option<Vec<u16>> = if current_directory.is_null() {
        None
    } else {
        Some(ansi_ptr_to_wide_vec(current_directory))
    };

    let app_ptr = app_wide
        .as_deref()
        .map_or(core::ptr::null(), <[u16]>::as_ptr);
    let cmd_ptr = cmd_wide
        .as_deref()
        .map_or(core::ptr::null_mut(), |v| v.as_ptr().cast_mut());
    let dir_ptr = dir_wide
        .as_deref()
        .map_or(core::ptr::null(), <[u16]>::as_ptr);

    kernel32_CreateProcessW(
        app_ptr,
        cmd_ptr,
        process_attributes,
        thread_attributes,
        inherit_handles,
        creation_flags,
        environment,
        dir_ptr,
        startup_info,
        process_information,
    )
}

/// CreateSymbolicLinkW - creates a symbolic link
///
/// Creates a symbolic link at `symlink_file_name` pointing to `target_file_name`.
/// `flags`: 0 = file link, 1 = directory link; the unprivileged-create flag (2)
/// is accepted but ignored on Linux (symlinks never require elevated privileges).
///
/// # Safety
/// `symlink_file_name` and `target_file_name` must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateSymbolicLinkW(
    symlink_file_name: *const u16,
    target_file_name: *const u16,
    _flags: u32,
) -> i32 {
    if symlink_file_name.is_null() || target_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let link_path = wide_path_to_linux(symlink_file_name);
    let target_path = wide_path_to_linux(target_file_name);
    match std::os::unix::fs::symlink(&target_path, &link_path) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 1,                                    // ERROR_INVALID_FUNCTION
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// CreateThread - creates a thread to execute within the virtual address space of the process
///
/// # Panics
/// Panics if the thread mutex is poisoned.
///
/// # Safety
/// `start_address` must be a valid Windows thread function (MS-x64 ABI).
/// `parameter` is passed as-is to the thread; the caller must ensure its validity.
/// `thread_id` must either be null or point to a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateThread(
    _thread_attributes: *mut core::ffi::c_void,
    _stack_size: usize,
    start_address: *mut core::ffi::c_void,
    parameter: *mut core::ffi::c_void,
    _creation_flags: u32,
    thread_id: *mut u32,
) -> *mut core::ffi::c_void {
    if start_address.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }

    // SAFETY: caller guarantees start_address is a valid Windows LPTHREAD_START_ROUTINE.
    let thread_fn: WindowsThreadStart = core::mem::transmute(start_address);
    let param_addr = parameter as usize;

    let exit_code: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
    let exit_code_clone = Arc::clone(&exit_code);

    // SAFETY: We spawn a thread that calls the Windows thread function.
    // param_addr is sent to the thread as a raw usize (avoiding Send requirement on *mut c_void).
    // The caller must ensure the parameter pointer remains valid for the thread's lifetime.
    let join_handle = thread::spawn(move || {
        let param_ptr = param_addr as *mut core::ffi::c_void;
        // SAFETY: thread_fn is a valid Windows thread function (MS-x64 ABI).
        let result = unsafe { thread_fn(param_ptr) };
        *exit_code_clone.lock().unwrap() = Some(result);
        result
    });

    let handle = alloc_thread_handle();
    with_thread_handles(|map| {
        map.insert(
            handle,
            ThreadEntry {
                join_handle: Some(join_handle),
                exit_code,
            },
        );
    });

    // Use the handle value (truncated) as the thread ID: non-zero and unique per thread.
    if !thread_id.is_null() {
        *thread_id = (handle & 0xFFFF_FFFF) as u32;
    }

    handle as *mut core::ffi::c_void
}

/// CreateToolhelp32Snapshot - creates a snapshot of processes, heaps, modules, and threads
///
/// Process and thread enumeration via the Toolhelp32 API is not supported in
/// this sandboxed environment.  Returns `INVALID_HANDLE_VALUE` and sets
/// `ERROR_NOT_SUPPORTED` (50).
///
/// # Safety
/// All arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateToolhelp32Snapshot(
    _flags: u32,
    _process_id: u32,
) -> *mut core::ffi::c_void {
    kernel32_SetLastError(50); // ERROR_NOT_SUPPORTED
    usize::MAX as *mut core::ffi::c_void // INVALID_HANDLE_VALUE
}

/// CreateWaitableTimerExW - creates or opens a waitable timer object
///
/// Waitable timers are not implemented in this sandboxed environment.
/// Returns NULL and sets `ERROR_NOT_SUPPORTED` (50).
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateWaitableTimerExW(
    _timer_attributes: *mut core::ffi::c_void,
    _timer_name: *const u16,
    _flags: u32,
    _desired_access: u32,
) -> *mut core::ffi::c_void {
    kernel32_SetLastError(50); // ERROR_NOT_SUPPORTED
    core::ptr::null_mut()
}

/// DeleteFileW - deletes a file
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteFileW(file_name: *const u16) -> i32 {
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    match std::fs::remove_file(std::path::Path::new(&path_str)) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// DeleteFileA - deletes a file (ANSI version)
///
/// Converts the narrow-character path to UTF-16 and delegates to
/// `kernel32_DeleteFileW`.
///
/// # Safety
/// `file_name` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteFileA(file_name: *const u8) -> i32 {
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path = std::ffi::CStr::from_ptr(file_name.cast::<i8>()).to_string_lossy();
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    kernel32_DeleteFileW(wide.as_ptr())
}

/// DeleteProcThreadAttributeList - deletes a process/thread attribute list
///
/// Since `InitializeProcThreadAttributeList` only zero-initialises the caller's
/// buffer, the list holds no heap-allocated resources.  No-op is the correct
/// implementation.
///
/// # Safety
/// This function never dereferences any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeleteProcThreadAttributeList(
    _attribute_list: *mut core::ffi::c_void,
) {
    // Attribute list holds no heap resources; nothing to free.
}

/// DeviceIoControl - sends a control code to a device driver
///
/// Arbitrary device I/O control codes cannot be dispatched without a real
/// device driver layer.  Returns FALSE and sets `ERROR_NOT_SUPPORTED` (50).
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DeviceIoControl(
    _device: *mut core::ffi::c_void,
    _io_control_code: u32,
    _in_buffer: *mut core::ffi::c_void,
    _in_buffer_size: u32,
    _out_buffer: *mut core::ffi::c_void,
    _out_buffer_size: u32,
    _bytes_returned: *mut u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    kernel32_SetLastError(50); // ERROR_NOT_SUPPORTED
    0 // FALSE
}

/// DuplicateHandle - duplicates an object handle
///
/// Only same-process duplication is supported (`source_process_handle` and
/// `target_process_handle` are accepted but their values are ignored).
///
/// For file handles, the underlying `File` is cloned via `try_clone()` so
/// the duplicate has its own file-offset cursor but refers to the same open
/// file description.  For event and thread handles the same handle value is
/// returned (they are already reference-counted via `Arc`).
///
/// # Safety
/// `target_handle` must be a valid writable pointer to a HANDLE when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DuplicateHandle(
    _source_process_handle: *mut core::ffi::c_void,
    source_handle: *mut core::ffi::c_void,
    _target_process_handle: *mut core::ffi::c_void,
    target_handle: *mut *mut core::ffi::c_void,
    _desired_access: u32,
    _inherit_handle: i32,
    _options: u32,
) -> i32 {
    if target_handle.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let src_val = source_handle as usize;

    // Try to duplicate as a file handle.
    let cloned = with_file_handles(|map| map.get(&src_val).and_then(|e| e.file.try_clone().ok()));
    if let Some(cloned_file) = cloned {
        let new_handle = alloc_file_handle();
        let inserted = with_file_handles(|map| {
            if map.len() >= MAX_OPEN_FILE_HANDLES {
                return false;
            }
            map.insert(new_handle, FileEntry::new(cloned_file));
            true
        });
        if inserted {
            *target_handle = new_handle as *mut core::ffi::c_void;
            return 1; // TRUE
        }
        kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return 0;
    }

    // For event handles, copy the value (they are Arc-backed and ref-counted).
    let is_event = with_event_handles(|map| map.contains_key(&src_val));
    if is_event {
        *target_handle = source_handle;
        return 1; // TRUE
    }

    // For thread handles, copy the value (join handles cannot be truly cloned).
    let is_thread = with_thread_handles(|map| map.contains_key(&src_val));
    if is_thread {
        *target_handle = source_handle;
        return 1; // TRUE
    }

    kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

/// FlushFileBuffers - flushes the write buffers of the specified file
///
/// In this implementation all writes are synchronous (backed directly by Linux
/// `write` syscalls), so there are no pending buffers to flush.  Always
/// returns TRUE.
///
/// # Safety
/// `file` is accepted as an opaque handle and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlushFileBuffers(_file: *mut core::ffi::c_void) -> i32 {
    1 // TRUE
}

/// FormatMessageW - formats a system error message or a custom message string
///
/// Supports `FORMAT_MESSAGE_FROM_SYSTEM` (0x1000): looks up the text for the
/// Windows error code given in `message_id` and writes it (as a null-terminated
/// UTF-16 string) into `buffer`.  When `FORMAT_MESSAGE_ALLOCATE_BUFFER`
/// (0x100) is also set, `buffer` is treated as a `*mut *mut u16`: a heap
/// buffer is allocated with `HeapAlloc` and its address is stored at
/// `*buffer`; the caller must free it with `HeapFree` / `LocalFree`.
///
/// Returns the number of UTF-16 code units written, excluding the null
/// terminator, or 0 on failure (sets last-error to
/// `ERROR_INSUFFICIENT_BUFFER` / `ERROR_INVALID_PARAMETER` as appropriate).
///
/// # Safety
/// * When `FORMAT_MESSAGE_ALLOCATE_BUFFER` is clear: `buffer` must be a
///   writable array of at least `size` UTF-16 code units.
/// * When `FORMAT_MESSAGE_ALLOCATE_BUFFER` is set: `buffer` must be a valid
///   `*mut *mut u16`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FormatMessageW(
    flags: u32,
    _source: *const core::ffi::c_void,
    message_id: u32,
    _language_id: u32,
    buffer: *mut u16,
    size: u32,
    _arguments: *mut *mut core::ffi::c_void,
) -> u32 {
    const FORMAT_MESSAGE_ALLOCATE_BUFFER: u32 = 0x0100;
    const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;

    if flags & FORMAT_MESSAGE_FROM_SYSTEM == 0 {
        // We only support FORMAT_MESSAGE_FROM_SYSTEM for now.
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let msg = windows_error_message(message_id);
    let utf16: Vec<u16> = msg.encode_utf16().chain(core::iter::once(0u16)).collect();
    let char_count = (utf16.len() - 1) as u32; // without null terminator

    if flags & FORMAT_MESSAGE_ALLOCATE_BUFFER != 0 {
        // buffer is actually a *mut *mut u16 — allocate heap memory and store pointer.
        if buffer.is_null() {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        let heap = kernel32_GetProcessHeap();
        let byte_len = utf16.len() * 2;
        let ptr = kernel32_HeapAlloc(heap, 0, byte_len).cast::<u16>();
        if ptr.is_null() {
            kernel32_SetLastError(14); // ERROR_OUTOFMEMORY
            return 0;
        }
        core::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
        *buffer.cast::<*mut u16>() = ptr;
        return char_count;
    }

    // Write to caller-supplied buffer.
    if buffer.is_null() || size == 0 {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    // Clamp to however many UTF-16 units fit (including the null terminator).
    // utf16.len() >= 1 because we always chain a null terminator above, so
    // to_write >= 1 whenever size >= 1, ruling out any underflow below.
    let to_write = utf16.len().min(size as usize);
    if to_write == 0 {
        return 0;
    }
    core::ptr::copy_nonoverlapping(utf16.as_ptr(), buffer, to_write);
    // Guarantee null termination at the last position written (handles truncation).
    *buffer.add(to_write - 1) = 0;
    // Return the number of characters written, not counting the null terminator.
    char_count.min(size - 1)
}

/// Returns the human-readable message for a Windows system error code.
fn windows_error_message(code: u32) -> String {
    let msg = match code {
        0 => "The operation completed successfully.",
        1 => "Incorrect function.",
        2 => "The system cannot find the file specified.",
        3 => "The system cannot find the path specified.",
        4 => "The system cannot open the file.",
        5 => "Access is denied.",
        6 => "The handle is invalid.",
        8 => "Not enough storage is available to process this command.",
        14 => "Not enough storage is available to complete this operation.",
        15 => "The system cannot find the drive specified.",
        16 => "The directory cannot be removed.",
        18 => "There are no more files.",
        32 => "The process cannot access the file because it is being used by another process.",
        87 => "The parameter is incorrect.",
        112 => "There is not enough space on the disk.",
        122 => "The data area passed to a system call is too small.",
        123 => "The filename, directory name, or volume label syntax is incorrect.",
        183 => "Cannot create a file when that file already exists.",
        206 => "The filename or extension is too long.",
        998 => "Invalid access to memory location.",
        1168 => "Element not found.",
        _ => return format!("Unknown error ({code})."),
    };
    msg.to_string()
}

/// GetCurrentDirectoryW - gets the current working directory
///
/// Returns the length of the path copied to the buffer (not including null terminator).
/// If the buffer is too small, returns the required buffer size (including null terminator).
///
/// # Safety
/// Caller must ensure buffer is valid and buffer_length is accurate if buffer is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentDirectoryW(
    buffer_length: u32,
    buffer: *mut u16,
) -> u32 {
    // Get current directory from std::env
    let Ok(current_dir) = std::env::current_dir() else {
        // Set last error to ERROR_ACCESS_DENIED (5)
        kernel32_SetLastError(5);
        return 0;
    };

    // Convert to string
    let dir_str = current_dir.to_string_lossy();

    // Convert Windows-style if needed (for consistency with Windows behavior)
    // But since we're on Linux, keep it as-is

    // Convert to UTF-16
    let mut utf16: Vec<u16> = dir_str.encode_utf16().collect();
    utf16.push(0); // Null terminator

    // Check if buffer is large enough
    if buffer.is_null() || buffer_length < utf16.len() as u32 {
        // Return required buffer size (including null terminator)
        return utf16.len() as u32;
    }

    // Copy to buffer
    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    // Return length without null terminator
    (utf16.len() - 1) as u32
}

/// GetExitCodeProcess — retrieves the termination status of a process.
///
/// Supports the current-process pseudo-handle (`-1 / 0xFFFF…`, returned by
/// `GetCurrentProcess()`) and handles returned by `CreateProcessW`.
/// For the pseudo-handle this function reports `STILL_ACTIVE` (259).
/// For spawned child processes the actual exit code is returned once the
/// process has exited; `STILL_ACTIVE` (259) is returned while it is running.
///
/// Any unrecognised handle value (including `NULL`) returns FALSE and sets
/// `ERROR_INVALID_HANDLE`.
///
/// # Safety
/// `exit_code` must be null or point to a writable `u32`.
///
/// # Panics
/// Panics if an internal mutex protecting child-process state is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetExitCodeProcess(
    process: *mut core::ffi::c_void,
    exit_code: *mut u32,
) -> i32 {
    const STILL_ACTIVE: u32 = 259;
    let handle_val = process as usize;
    // The Windows current-process pseudo-handle is -1 (all bits set).
    let current_process = kernel32_GetCurrentProcess();
    if process == current_process {
        if !exit_code.is_null() {
            // SAFETY: Caller guarantees exit_code is valid and non-null (checked above).
            *exit_code = STILL_ACTIVE;
        }
        return 1; // TRUE
    }

    // Check process handle registry.
    let proc_info = with_process_handles(|map| {
        map.get(&handle_val)
            .map(|e| (Arc::clone(&e.child), Arc::clone(&e.exit_code)))
    });
    if let Some((child_arc, ec_arc)) = proc_info {
        // Try to reap the child if it hasn't been waited on yet.
        {
            let mut guard = child_arc.lock().unwrap();
            if ec_arc.lock().unwrap().is_none()
                && let Some(ref mut child) = *guard
                && let Ok(Some(status)) = child.try_wait()
            {
                let code = status.code().map_or(1, |c| c as u32);
                *ec_arc.lock().unwrap() = Some(code);
                *guard = None;
            }
        }
        let code = ec_arc.lock().unwrap().unwrap_or(STILL_ACTIVE);
        if !exit_code.is_null() {
            // SAFETY: Caller guarantees exit_code points to valid writable memory.
            *exit_code = code;
        }
        return 1; // TRUE
    }

    kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
    0 // FALSE
}

/// GetFileAttributesW - gets file attributes
///
/// Returns `FILE_ATTRIBUTE_DIRECTORY` for directories, `FILE_ATTRIBUTE_NORMAL`
/// for regular files, and `INVALID_FILE_ATTRIBUTES` (0xFFFF_FFFF) if the path
/// does not exist or cannot be accessed.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileAttributesW(file_name: *const u16) -> u32 {
    const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0080;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_FILE_ATTRIBUTES;
    }
    let path_str = wide_path_to_linux(file_name);
    if let Ok(meta) = std::fs::metadata(std::path::Path::new(&path_str)) {
        if meta.is_dir() {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            let mut attrs = FILE_ATTRIBUTE_NORMAL;
            if meta.permissions().readonly() {
                attrs |= FILE_ATTRIBUTE_READONLY;
            }
            attrs
        }
    } else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        INVALID_FILE_ATTRIBUTES
    }
}

/// GetFileInformationByHandle — retrieves file information for the specified file.
///
/// Fills the caller-supplied `BY_HANDLE_FILE_INFORMATION` structure (52 bytes,
/// 13 consecutive `u32` fields) using `fstat` on the underlying Linux file descriptor.
///
/// # Safety
/// `file` must be a handle previously returned by `CreateFileW`.
/// `file_information` must point to a writable 52-byte `BY_HANDLE_FILE_INFORMATION` struct.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandle(
    file: *mut core::ffi::c_void,
    file_information: *mut core::ffi::c_void,
) -> i32 {
    // Windows FILETIME: 100-nanosecond intervals since 1601-01-01 UTC.
    // Unix time: seconds since 1970-01-01 UTC.  Difference: 11 644 473 600 s.
    const UNIX_EPOCH_OFFSET: u64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    if file_information.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let handle_val = file as usize;

    // Retrieve metadata from the registered file handle (calls fstat internally).
    let result = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.metadata()));

    let Some(meta_result) = result else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let Ok(meta) = meta_result else {
        kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
        return 0;
    };

    let to_filetime = |secs: i64, nsecs: i64| -> u64 {
        if secs < 0 {
            return 0;
        }
        let whole_ticks = (secs as u64)
            .saturating_add(UNIX_EPOCH_OFFSET)
            .saturating_mul(TICKS_PER_SEC);
        // Add the sub-second nanosecond component (1 tick = 100 ns).
        let sub_ticks = (nsecs.max(0) as u64) / 100;
        whole_ticks.saturating_add(sub_ticks)
    };

    let attrs: u32 =
        if meta.is_dir() { 0x10 } else { 0x80 } | u32::from(meta.permissions().readonly());
    let file_size = meta.len();
    let mtime = to_filetime(meta.mtime(), meta.mtime_nsec());
    let atime = to_filetime(meta.atime(), meta.atime_nsec());
    // Linux has no "creation time"; use ctime (metadata-change time) as approximation.
    let ctime = to_filetime(meta.ctime(), meta.ctime_nsec());
    let ino = meta.ino();
    let nlink = meta.nlink();

    // BY_HANDLE_FILE_INFORMATION layout (13 × u32 = 52 bytes):
    //  [0]     dwFileAttributes
    //  [1,2]   ftCreationTime    (low32, high32)
    //  [3,4]   ftLastAccessTime  (low32, high32)
    //  [5,6]   ftLastWriteTime   (low32, high32)
    //  [7]     dwVolumeSerialNumber
    //  [8]     nFileSizeHigh
    //  [9]     nFileSizeLow
    //  [10]    nNumberOfLinks
    //  [11]    nFileIndexHigh
    //  [12]    nFileIndexLow
    // SAFETY: Caller guarantees file_information points to a valid 52-byte struct.
    let p = file_information.cast::<u32>();
    *p.add(0) = attrs;
    *p.add(1) = ctime as u32;
    *p.add(2) = (ctime >> 32) as u32;
    *p.add(3) = atime as u32;
    *p.add(4) = (atime >> 32) as u32;
    *p.add(5) = mtime as u32;
    *p.add(6) = (mtime >> 32) as u32;
    *p.add(7) = get_volume_serial();
    *p.add(8) = (file_size >> 32) as u32;
    *p.add(9) = file_size as u32;
    *p.add(10) = nlink as u32;
    *p.add(11) = (ino >> 32) as u32;
    *p.add(12) = ino as u32;

    kernel32_SetLastError(0); // SUCCESS
    1 // TRUE
}

/// GetFileType - gets the type of a file
///
/// Returns FILE_TYPE_CHAR (2) for the standard console handles, FILE_TYPE_DISK (1)
/// for handles opened with CreateFileW, and FILE_TYPE_UNKNOWN (0) otherwise.
///
/// # Safety
/// This function is safe to call; `file` is treated as an opaque handle value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileType(file: *mut core::ffi::c_void) -> u32 {
    const FILE_TYPE_DISK: u32 = 1;
    const FILE_TYPE_CHAR: u32 = 2;
    const FILE_TYPE_UNKNOWN: u32 = 0;

    let handle_val = file as usize;
    // 0x10 = stdin, 0x11 = stdout, 0x12 = stderr (see GetStdHandle)
    if handle_val == 0x10 || handle_val == 0x11 || handle_val == 0x12 {
        return FILE_TYPE_CHAR;
    }
    if with_file_handles(|map| map.contains_key(&handle_val)) {
        return FILE_TYPE_DISK;
    }
    FILE_TYPE_UNKNOWN
}

/// GetFullPathNameW - gets the absolute path name of a file
///
/// Converts a potentially relative path to an absolute one using the current
/// working directory.  The `file_part` pointer (if non-null) is set to point
/// at the file name portion of the result inside `buffer`.
///
/// Returns the number of characters written (excluding the null terminator),
/// or the required buffer length (including the null terminator) if the buffer
/// is too small, or 0 on error.
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
/// `buffer` must point to a writable area of at least `buffer_length` `u16`s, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFullPathNameW(
    file_name: *const u16,
    buffer_length: u32,
    buffer: *mut u16,
    file_part: *mut *mut u16,
) -> u32 {
    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    // Resolve to an absolute path
    let abs_path = if std::path::Path::new(&path_str).is_absolute() {
        path_str.clone()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(&path_str).to_string_lossy().into_owned(),
            Err(_) => path_str.clone(),
        }
    };

    let utf16: Vec<u16> = abs_path.encode_utf16().collect();
    let required = utf16.len() as u32 + 1; // +1 for null terminator

    if buffer.is_null() || buffer_length == 0 {
        return required;
    }
    if buffer_length < required {
        // Buffer too small – return required size (including null)
        kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return required;
    }
    for (i, &ch) in utf16.iter().enumerate() {
        // SAFETY: we checked buffer_length >= required
        core::ptr::write(buffer.add(i), ch);
    }
    core::ptr::write(buffer.add(utf16.len()), 0u16);

    // Set *file_part to point at the final component (the filename) inside buffer
    if !file_part.is_null() {
        let last_sep = utf16
            .iter()
            .rposition(|&c| c == u16::from(b'/') || c == u16::from(b'\\'));
        let fname_offset = match last_sep {
            Some(pos) => pos + 1,
            None => 0,
        };
        if fname_offset < utf16.len() {
            // SAFETY: fname_offset < utf16.len() < required <= buffer_length
            *file_part = buffer.add(fname_offset);
        } else {
            *file_part = core::ptr::null_mut();
        }
    }

    utf16.len() as u32 // number of chars written (excluding null)
}

// Thread-local storage for last error codes
//
// Each thread maintains its own error code without global synchronization.
// This eliminates the unbounded memory growth issue from the previous
// implementation and improves performance by removing mutex contention.
thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// GetLastError - gets the last error code for the current thread
///
/// In Windows, this is thread-local and set by many APIs.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLastError() -> u32 {
    LAST_ERROR.with(Cell::get)
}

/// GetModuleHandleW - retrieves the module handle for the specified module
///
/// When `module_name` is null, returns the base address of the main executable
/// (`0x400000`).  For named DLLs, looks up the handle in the dynamic-export
/// registry populated by `register_dynamic_exports`.  Returns NULL with
/// `ERROR_MOD_NOT_FOUND` (126) if the named DLL is not registered.
///
/// # Safety
/// `module_name` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleW(
    module_name: *const u16,
) -> *mut core::ffi::c_void {
    if module_name.is_null() {
        // Return a fake non-null handle for the main module
        return 0x400000 as *mut core::ffi::c_void;
    }
    let name = wide_str_to_string(module_name);
    let upper = dll_basename(&name).to_uppercase();
    let handle = with_dll_handles(|reg| reg.by_name.get(&upper).copied());
    if let Some(h) = handle {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(126); // ERROR_MOD_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// GetProcAddress - retrieves the address of an exported function or variable
///
/// Looks up `proc_name` in the dynamic-export registry for the DLL identified
/// by `module`.  When `proc_name as usize < 0x10000` it is treated as an
/// ordinal (not supported; returns NULL with `ERROR_PROC_NOT_FOUND`).
///
/// Returns the trampoline function address on success, or NULL with
/// `ERROR_PROC_NOT_FOUND` (127) on failure.
///
/// # Safety
/// `module` must be a handle returned by `LoadLibraryA/W` or `GetModuleHandleA/W`.
/// `proc_name` must be either a valid null-terminated ANSI string (when ≥ 0x10000)
/// or an ordinal value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcAddress(
    module: *mut core::ffi::c_void,
    proc_name: *const u8,
) -> *mut core::ffi::c_void {
    let handle = module as usize;
    // Ordinal check: Windows encodes ordinals as values below 0x10000 (64 KB).
    // Any pointer above that boundary is a valid user-space address on all
    // supported Windows/Linux platforms.  See MAKEINTRESOURCE / HIWORD(proc_name).
    if (proc_name as usize) < 0x10000 {
        kernel32_SetLastError(127); // ERROR_PROC_NOT_FOUND
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees proc_name is a valid null-terminated ANSI string.
    let name = std::ffi::CStr::from_ptr(proc_name.cast::<i8>()).to_string_lossy();
    let addr = with_dll_handles(|reg| {
        reg.by_handle
            .get(&handle)
            .and_then(|entry| entry.exports.get(name.as_ref()).copied())
    });
    match addr {
        Some(a) if a != 0 => a as *mut core::ffi::c_void,
        _ => {
            kernel32_SetLastError(127); // ERROR_PROC_NOT_FOUND
            core::ptr::null_mut()
        }
    }
}

/// GetStdHandle - retrieves a handle to the specified standard device
///
/// Returns:
/// - `0x10` for `STD_INPUT_HANDLE`  (-10 / 0xFFFFFFF6)
/// - `0x11` for `STD_OUTPUT_HANDLE` (-11 / 0xFFFFFFF5)
/// - `0x12` for `STD_ERROR_HANDLE`  (-12 / 0xFFFFFFF4)
/// - `NULL` for any other value
///
/// These sentinel values are recognised by `WriteFile`, `ReadFile`, and
/// `GetFileType` as the console handles.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStdHandle(std_handle: u32) -> *mut core::ffi::c_void {
    // STD_INPUT_HANDLE = -10, STD_OUTPUT_HANDLE = -11, STD_ERROR_HANDLE = -12
    #[allow(clippy::cast_possible_wrap)]
    match std_handle as i32 {
        -10 => 0x10 as *mut core::ffi::c_void, // stdin
        -11 => 0x11 as *mut core::ffi::c_void, // stdout
        -12 => 0x12 as *mut core::ffi::c_void, // stderr
        _ => core::ptr::null_mut(),
    }
}

/// GetCommandLineW - returns the command line for the current process (wide version)
///
/// Returns a pointer to the process command line as a null-terminated UTF-16 string.
/// The runner must call `set_process_command_line` before the entry point executes.
///
/// # Safety
/// This function is safe to call. It returns a pointer to static storage that is valid
/// for the lifetime of the process.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCommandLineW() -> *const u16 {
    // SAFETY: The Vec stored in PROCESS_COMMAND_LINE is never dropped; as_ptr() is valid.
    // EMPTY_CMD is a const array; its address is stable for the lifetime of the process.
    const EMPTY_CMD: [u16; 1] = [0];
    PROCESS_COMMAND_LINE
        .get()
        .map_or(EMPTY_CMD.as_ptr(), std::vec::Vec::as_ptr)
}

/// GetEnvironmentStringsW - returns all environment strings as a UTF-16 block
///
/// Returns a pointer to a freshly allocated block of null-terminated wide strings
/// of the form `NAME=VALUE\0NAME2=VALUE2\0\0`.  Each call allocates a new block;
/// the caller must release it with `FreeEnvironmentStringsW` to avoid a memory leak.
///
/// # Panics
/// Panics if the environment strings mutex is poisoned.
///
/// # Safety
/// This function is safe to call. The returned pointer is valid until
/// `FreeEnvironmentStringsW` is called with the same pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentStringsW() -> *mut u16 {
    let mut block: Vec<u16> = Vec::new();
    for (key, value) in std::env::vars() {
        let entry = format!("{key}={value}");
        block.extend(entry.encode_utf16());
        block.push(0); // null terminator for this entry
    }
    block.push(0); // final null terminator (empty string = end of block)

    let len = block.len();
    let boxed = block.into_boxed_slice();
    // SAFETY: We just allocated this box; we record the raw pointer so that
    // FreeEnvironmentStringsW can reconstruct the Box and drop it.
    let raw = Box::into_raw(boxed).cast::<u16>();

    let mut guard = ENV_STRINGS_BLOCKS.lock().unwrap();
    guard.get_or_insert_with(Vec::new).push(SendablePtr(raw));
    drop(guard);

    // Suppress unused-variable warning for `len` (used only as a sanity note).
    let _ = len;
    raw
}

/// FreeEnvironmentStringsW - frees a block returned by `GetEnvironmentStringsW`
///
/// Reconstructs the `Box<[u16]>` from the pointer and drops it.  If the pointer
/// was not returned by `GetEnvironmentStringsW`, this is a no-op (safe but does not
/// free the memory).
///
/// # Panics
/// Panics if the environment strings mutex is poisoned.
///
/// # Safety
/// `env_strings` must be a pointer previously returned by `GetEnvironmentStringsW`,
/// or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeEnvironmentStringsW(env_strings: *mut u16) -> i32 {
    if env_strings.is_null() {
        return 1; // TRUE
    }
    let mut guard = ENV_STRINGS_BLOCKS.lock().unwrap();
    let blocks = guard.get_or_insert_with(Vec::new);
    if let Some(pos) = blocks.iter().position(|p| p.0 == env_strings) {
        let ptr = blocks.swap_remove(pos).0;
        drop(guard);
        // Reconstruct the slice length by scanning for the double-null terminator,
        // then drop the box.  We need the length to build a fat pointer.
        //
        // SAFETY: `ptr` was created by `Box::into_raw(boxed.into_boxed_slice())` in
        // `GetEnvironmentStringsW`; we are the only owner now that we removed it from
        // the registry.  We scan to re-derive the original slice length.
        let mut len = 0usize;
        loop {
            if *ptr.add(len) == 0 && *ptr.add(len + 1) == 0 {
                len += 2; // include both null terminators
                break;
            }
            len += 1;
        }
        let slice_ptr = core::ptr::slice_from_raw_parts_mut(ptr, len);
        drop(Box::from_raw(slice_ptr));
    }
    1 // TRUE
}

/// LoadLibraryA - loads a dynamic-link library (ANSI version)
///
/// Looks up the DLL in the dynamic-export registry populated by
/// `register_dynamic_exports`.  The path is stripped to its file-name
/// component before the case-insensitive lookup, so both bare names
/// (`"kernel32.dll"`) and full paths (`"C:\\Windows\\system32\\kernel32.dll"`)
/// are accepted.
///
/// Returns a non-null synthetic HMODULE on success, or NULL with
/// `ERROR_MOD_NOT_FOUND` (126) if the DLL is not registered.
///
/// # Safety
/// `lib_file_name` must be a valid null-terminated ANSI string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryA(lib_file_name: *const u8) -> *mut core::ffi::c_void {
    if lib_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees lib_file_name is a valid null-terminated C string.
    let name = std::ffi::CStr::from_ptr(lib_file_name.cast::<i8>()).to_string_lossy();
    let upper = dll_basename(name.as_ref()).to_uppercase();
    let handle = with_dll_handles(|reg| reg.by_name.get(&upper).copied());
    if let Some(h) = handle {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(126); // ERROR_MOD_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// LoadLibraryW - loads a dynamic-link library (wide-string version)
///
/// Looks up the DLL in the dynamic-export registry populated by
/// `register_dynamic_exports`.  The path is stripped to its file-name
/// component before the case-insensitive lookup.
///
/// Returns a non-null synthetic HMODULE on success, or NULL with
/// `ERROR_MOD_NOT_FOUND` (126) if the DLL is not registered.
///
/// # Safety
/// `lib_file_name` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LoadLibraryW(
    lib_file_name: *const u16,
) -> *mut core::ffi::c_void {
    if lib_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }
    let name = wide_str_to_string(lib_file_name);
    let upper = dll_basename(&name).to_uppercase();
    let handle = with_dll_handles(|reg| reg.by_name.get(&upper).copied());
    if let Some(h) = handle {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(126); // ERROR_MOD_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// SetConsoleCtrlHandler - adds or removes a console control handler
///
/// Returns TRUE to indicate the request was accepted.  SIGINT and other
/// console control events are delivered as Linux signals and are not currently
/// routed to the registered handler function; the default process-termination
/// behavior is preserved.  For programs that only register a handler to
/// prevent the default Ctrl+C termination, this is the correct behavior.
///
/// # Safety
/// `handler_routine` is accepted as an opaque pointer; it is not called or
/// dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleCtrlHandler(
    _handler_routine: *mut core::ffi::c_void,
    _add: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SetFilePointerEx - moves the file pointer of the specified file
///
/// Translates Windows `move_method` (FILE_BEGIN=0, FILE_CURRENT=1, FILE_END=2) to
/// a `std::io::SeekFrom` and calls `seek()` on the file registered in the handle map.
///
/// # Safety
/// `new_file_pointer` may be null; when non-null it must be a valid writable `i64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFilePointerEx(
    file: *mut core::ffi::c_void,
    distance_to_move: i64,
    new_file_pointer: *mut i64,
    move_method: u32,
) -> i32 {
    let handle_val = file as usize;
    let seek_from = match move_method {
        0 => {
            if distance_to_move < 0 {
                // Windows: SetFilePointerEx(FILE_BEGIN, negative) -> ERROR_NEGATIVE_SEEK (131)
                kernel32_SetLastError(131);
                return 0;
            }
            std::io::SeekFrom::Start(distance_to_move as u64) // FILE_BEGIN
        }
        1 => std::io::SeekFrom::Current(distance_to_move), // FILE_CURRENT
        2 => std::io::SeekFrom::End(distance_to_move),     // FILE_END
        _ => {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
    };
    let result = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.seek(seek_from).ok().map(|pos| pos as i64)
        } else {
            None
        }
    });
    if let Some(pos) = result {
        if !new_file_pointer.is_null() {
            *new_file_pointer = pos;
        }
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        0 // FALSE
    }
}

/// SetLastError - sets the last error code for the current thread
///
/// In Windows, this is thread-local storage used by many APIs to report errors.
/// This implementation uses true thread-local storage for optimal performance.
///
/// # Safety
/// The function body is safe, but marked `unsafe` because it's part of an FFI boundary
/// with `extern "C"` calling convention. Callers must ensure proper calling convention.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetLastError(error_code: u32) {
    LAST_ERROR.with(|error| error.set(error_code));
}

/// Result type for sync handle wait operations inside `kernel32_WaitForSingleObject`.
enum SyncWaitResult {
    MutexAcquired,
    MutexTimeout,
    SemaphoreAcquired,
    SemaphoreTimeout,
}

/// WaitForSingleObject - waits until the specified object is in the signaled state or the
/// time-out interval elapses.
///
/// For event handles (created by `CreateEventW`), this waits with correct
/// manual/auto-reset semantics. `INFINITE` (0xFFFFFFFF) blocks until the event
/// is signaled; finite timeouts use a deadline loop that handles spurious
/// wakeups and returns immediately when the event is already signaled.
///
/// For thread handles (created by `CreateThread`), this joins the thread.
///
/// For unrecognised handles (neither event nor thread), `WAIT_OBJECT_0` is
/// returned immediately as an optimistic default.
///
/// # Panics
/// Panics if a mutex protecting event or thread state is poisoned.
///
/// # Safety
/// `handle` must be a valid handle returned by `CreateEventW`, `CreateThread`,
/// or another handle-producing API.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForSingleObject(
    handle: *mut core::ffi::c_void,
    milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    let handle_val = handle as usize;

    // Check if this is an event handle first.
    let event_entry = with_event_handles(|map| {
        map.get(&handle_val)
            .map(|e| (Arc::clone(&e.state), e.manual_reset))
    });
    if let Some((state, manual_reset)) = event_entry {
        let (lock, cvar) = &*state;
        let mut signaled = lock.lock().unwrap();
        if milliseconds == u32::MAX {
            // Infinite wait until the event is signaled.
            while !*signaled {
                signaled = cvar.wait(signaled).unwrap();
            }
            if !manual_reset {
                *signaled = false; // auto-reset
            }
            return WAIT_OBJECT_0;
        }

        // Finite-timeout wait.
        //
        // Return immediately if the event is already signaled.
        if *signaled {
            if !manual_reset {
                *signaled = false; // auto-reset
            }
            return WAIT_OBJECT_0;
        }

        // Zero-timeout: check-and-return without blocking.
        if milliseconds == 0 {
            return WAIT_TIMEOUT;
        }

        // Loop to handle spurious wakeups and recompute remaining time.
        let timeout = Duration::from_millis(u64::from(milliseconds));
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if *signaled {
                if !manual_reset {
                    *signaled = false; // auto-reset
                }
                return WAIT_OBJECT_0;
            }

            let now = std::time::Instant::now();
            if now >= deadline {
                return WAIT_TIMEOUT;
            }

            let remaining = deadline - now;
            let (guard, result) = cvar.wait_timeout(signaled, remaining).unwrap();
            signaled = guard;

            // If the Condvar reported a genuine timeout and the event is still not
            // signaled, report WAIT_TIMEOUT.  Otherwise loop to recheck *signaled.
            if result.timed_out() && !*signaled {
                return WAIT_TIMEOUT;
            }
        }
    }

    // Check sync handles (mutex / semaphore)
    let sync_result: Option<SyncWaitResult> = with_sync_handles(|map| {
        if let Some(entry) = map.get(&handle_val) {
            match entry {
                SyncObjectEntry::Mutex { state, .. } => {
                    let (lock, cvar) = &**state;
                    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                    let mut guard = lock.lock().unwrap();
                    if let Some((owner, count)) = *guard
                        && owner == tid
                    {
                        *guard = Some((owner, count + 1));
                        return Some(SyncWaitResult::MutexAcquired);
                    }
                    if milliseconds == u32::MAX {
                        while guard.is_some() {
                            guard = cvar.wait(guard).unwrap();
                        }
                        *guard = Some((tid, 1));
                        return Some(SyncWaitResult::MutexAcquired);
                    }
                    if guard.is_none() {
                        *guard = Some((tid, 1));
                        return Some(SyncWaitResult::MutexAcquired);
                    }
                    if milliseconds == 0 {
                        return Some(SyncWaitResult::MutexTimeout);
                    }
                    let timeout = Duration::from_millis(u64::from(milliseconds));
                    let deadline = std::time::Instant::now() + timeout;
                    loop {
                        if guard.is_none() {
                            *guard = Some((tid, 1));
                            return Some(SyncWaitResult::MutexAcquired);
                        }
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            return Some(SyncWaitResult::MutexTimeout);
                        }
                        let remaining = deadline - now;
                        let (g, result) = cvar.wait_timeout(guard, remaining).unwrap();
                        guard = g;
                        if result.timed_out() && guard.is_some() {
                            return Some(SyncWaitResult::MutexTimeout);
                        }
                    }
                }
                SyncObjectEntry::Semaphore { state, .. } => {
                    let (lock, cvar) = &**state;
                    let mut count = lock.lock().unwrap();
                    if milliseconds == u32::MAX {
                        while *count == 0 {
                            count = cvar.wait(count).unwrap();
                        }
                        *count -= 1;
                        return Some(SyncWaitResult::SemaphoreAcquired);
                    }
                    if *count > 0 {
                        *count -= 1;
                        return Some(SyncWaitResult::SemaphoreAcquired);
                    }
                    if milliseconds == 0 {
                        return Some(SyncWaitResult::SemaphoreTimeout);
                    }
                    let timeout = Duration::from_millis(u64::from(milliseconds));
                    let deadline = std::time::Instant::now() + timeout;
                    loop {
                        if *count > 0 {
                            *count -= 1;
                            return Some(SyncWaitResult::SemaphoreAcquired);
                        }
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            return Some(SyncWaitResult::SemaphoreTimeout);
                        }
                        let remaining = deadline - now;
                        let (g, result) = cvar.wait_timeout(count, remaining).unwrap();
                        count = g;
                        if result.timed_out() && *count == 0 {
                            return Some(SyncWaitResult::SemaphoreTimeout);
                        }
                    }
                }
            }
        } else {
            None
        }
    });
    match sync_result {
        Some(SyncWaitResult::MutexAcquired | SyncWaitResult::SemaphoreAcquired) => {
            return WAIT_OBJECT_0;
        }
        Some(SyncWaitResult::MutexTimeout | SyncWaitResult::SemaphoreTimeout) => {
            return WAIT_TIMEOUT;
        }
        None => {}
    }

    // Take ownership of the join handle (if this is a thread handle).
    let thread_entry = with_thread_handles(|map| {
        map.get_mut(&handle_val).map(|entry| {
            let jh = entry.join_handle.take();
            let ec = Arc::clone(&entry.exit_code);
            (jh, ec)
        })
    });

    let Some((join_handle_opt, exit_code)) = thread_entry else {
        // Check if this is a process handle.
        let process_entry = with_process_handles(|map| {
            map.get(&handle_val)
                .map(|e| (Arc::clone(&e.child), Arc::clone(&e.exit_code)))
        });
        if let Some((child_arc, ec_arc)) = process_entry {
            // Poll the child for completion.
            let poll_child = || -> bool {
                let mut guard = child_arc.lock().unwrap();
                if ec_arc.lock().unwrap().is_some() {
                    return true;
                }
                if let Some(ref mut child) = *guard
                    && let Ok(Some(status)) = child.try_wait()
                {
                    let code = status.code().map_or(1, |c| c as u32);
                    *ec_arc.lock().unwrap() = Some(code);
                    *guard = None;
                    return true;
                }
                false
            };

            if milliseconds == u32::MAX {
                // Infinite wait: block until the child exits.
                loop {
                    if poll_child() {
                        return WAIT_OBJECT_0;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
            }

            if milliseconds == 0 {
                return if poll_child() {
                    WAIT_OBJECT_0
                } else {
                    WAIT_TIMEOUT
                };
            }

            let start = std::time::Instant::now();
            let timeout = Duration::from_millis(u64::from(milliseconds));
            loop {
                if poll_child() {
                    return WAIT_OBJECT_0;
                }
                if start.elapsed() >= timeout {
                    return WAIT_TIMEOUT;
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
        // Not a thread, event, or process handle — treat as already-signaled.
        return WAIT_OBJECT_0;
    };

    let Some(join_handle) = join_handle_opt else {
        // Thread was already joined.
        return WAIT_OBJECT_0;
    };

    if milliseconds == u32::MAX {
        // Infinite wait: block until the thread finishes.
        let _ = join_handle.join();
        return WAIT_OBJECT_0;
    }

    // Timed wait: poll the exit code with 1 ms sleep intervals.
    let start = std::time::Instant::now();
    let timeout = Duration::from_millis(u64::from(milliseconds));
    loop {
        if exit_code.lock().unwrap().is_some() {
            let _ = join_handle.join();
            return WAIT_OBJECT_0;
        }
        if start.elapsed() >= timeout {
            // Return the join handle to the registry so the thread can be joined later.
            with_thread_handles(|map| {
                if let Some(entry) = map.get_mut(&handle_val) {
                    entry.join_handle = Some(join_handle);
                }
            });
            return WAIT_TIMEOUT;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

/// WaitForSingleObjectEx
///
/// When `alertable` is non-zero, any pending APC callbacks queued by
/// `ReadFileEx` or `WriteFileEx` are executed and `WAIT_IO_COMPLETION`
/// (0x00C0) is returned immediately without waiting on the handle.
/// When `alertable` is zero the behaviour matches `WaitForSingleObject`.
///
/// # Safety
/// Safe to call with any handle value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForSingleObjectEx(
    handle: *mut core::ffi::c_void,
    milliseconds: u32,
    alertable: i32,
) -> u32 {
    if alertable != 0 {
        let had_apcs = drain_apc_queue();
        if had_apcs {
            return 0xC0; // WAIT_IO_COMPLETION
        }
    }
    unsafe { kernel32_WaitForSingleObject(handle, milliseconds) }
}

/// WriteConsoleW - writes a character string to a console screen buffer
///
/// Converts the wide (UTF-16) string to UTF-8 and writes it to `stdout`.
/// The `console_output` handle is accepted but not used to distinguish between
/// stdout and stderr; all output goes to stdout.  Returns FALSE if `buffer`
/// is null, `number_of_chars_to_write` is zero, or the UTF-16 string is not
/// valid.
///
/// # Safety
/// `buffer` must point to at least `number_of_chars_to_write` valid UTF-16
/// code units when non-null.  `number_of_chars_written`, if non-null, must
/// point to a writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteConsoleW(
    _console_output: *mut core::ffi::c_void,
    buffer: *const u16,
    number_of_chars_to_write: u32,
    number_of_chars_written: *mut u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    // Try to write to stdout
    if !buffer.is_null() && number_of_chars_to_write > 0 {
        let slice = core::slice::from_raw_parts(buffer, number_of_chars_to_write as usize);
        if let Ok(s) = String::from_utf16(slice) {
            print!("{s}");
            let _ = std::io::stdout().flush();
            if !number_of_chars_written.is_null() {
                *number_of_chars_written = number_of_chars_to_write;
            }
            return 1; // TRUE
        }
    }
    0 // FALSE
}

/// WriteConsoleA - writes an ANSI character string to a console screen buffer
///
/// Writes `number_of_chars_to_write` bytes from the byte buffer `buffer` to
/// stdout, treating the data as UTF-8 (or Latin-1 for non-UTF-8 bytes).
///
/// # Safety
/// `buffer` must point to at least `number_of_chars_to_write` valid bytes
/// when non-null.  `number_of_chars_written`, if non-null, must point to a
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteConsoleA(
    _console_output: *mut core::ffi::c_void,
    buffer: *const u8,
    number_of_chars_to_write: u32,
    number_of_chars_written: *mut u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    use std::io::Write as _;
    if !buffer.is_null() && number_of_chars_to_write > 0 {
        let slice = core::slice::from_raw_parts(buffer, number_of_chars_to_write as usize);
        // Best-effort UTF-8 interpretation; non-UTF-8 bytes are replaced.
        let s = String::from_utf8_lossy(slice);
        let _ = std::io::stdout().write_all(s.as_bytes());
        let _ = std::io::stdout().flush();
        if !number_of_chars_written.is_null() {
            *number_of_chars_written = number_of_chars_to_write;
        }
        return 1; // TRUE
    }
    0 // FALSE
}

// Additional stubs for remaining missing APIs

/// GetFileInformationByHandleEx - retrieves file information by file handle
///
/// Supports two information classes:
/// - `FileBasicInfo` (0): timestamps and file attributes.
/// - `FileStandardInfo` (1): file size, link count, directory flag.
///
/// Returns FALSE for unknown classes (`ERROR_INVALID_PARAMETER`).
///
/// # Safety
/// `file_information` must point to a writable buffer of at least
/// `buffer_size` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileInformationByHandleEx(
    file: *mut core::ffi::c_void,
    file_information_class: u32,
    file_information: *mut core::ffi::c_void,
    buffer_size: u32,
) -> i32 {
    if file_information.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let handle_val = file as usize;
    let meta = with_file_handles(|map| map.get(&handle_val).and_then(|e| e.file.metadata().ok()));
    let Some(meta) = meta else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };

    match file_information_class {
        0 => {
            // FileBasicInfo: CreationTime, LastAccessTime, LastWriteTime, ChangeTime, FileAttributes
            // Layout: 4 × i64 (32 bytes) + u32 (4 bytes) = 36 bytes total.
            if buffer_size < 36 {
                kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            let buf = file_information.cast::<u8>();
            // Zero the whole struct first.
            // SAFETY: Caller guarantees buffer is writable for buffer_size bytes (checked ≥ 36).
            std::ptr::write_bytes(buf, 0, 36);

            // Convert a Unix timestamp (seconds + nanoseconds) to a Windows FILETIME
            // (100-nanosecond intervals since 1601-01-01).
            let to_filetime =
                |secs: i64, nsec: i64| -> i64 { (secs + EPOCH_DIFF) * 10_000_000 + nsec / 100 };

            // Linux has no dedicated "creation time"; use ctime (metadata-change time)
            // as the closest approximation.
            let creation = to_filetime(meta.ctime(), meta.ctime_nsec());
            let atime = to_filetime(meta.atime(), meta.atime_nsec());
            let mtime = to_filetime(meta.mtime(), meta.mtime_nsec());
            let ctime = to_filetime(meta.ctime(), meta.ctime_nsec());

            // SAFETY: buffer is at least 36 bytes, offsets are within bounds.
            std::ptr::write_unaligned(buf.add(0).cast::<i64>(), creation);
            std::ptr::write_unaligned(buf.add(8).cast::<i64>(), atime);
            std::ptr::write_unaligned(buf.add(16).cast::<i64>(), mtime);
            std::ptr::write_unaligned(buf.add(24).cast::<i64>(), ctime);

            let attrs: u32 = if meta.is_dir() {
                0x10 // FILE_ATTRIBUTE_DIRECTORY
            } else if meta.mode() & 0o200 == 0 {
                0x01 // FILE_ATTRIBUTE_READONLY
            } else {
                0x80 // FILE_ATTRIBUTE_NORMAL
            };
            // SAFETY: offset 32 is within the 36-byte buffer.
            std::ptr::write_unaligned(buf.add(32).cast::<u32>(), attrs);
            1 // TRUE
        }
        1 => {
            // FileStandardInfo: AllocationSize, EndOfFile, NumberOfLinks,
            //                   DeletePending, Directory
            // Layout: i64 (8) + i64 (8) + u32 (4) + u8 (1) + u8 (1) = 22 bytes.
            if buffer_size < 22 {
                kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
                return 0;
            }
            let buf = file_information.cast::<u8>();
            // SAFETY: Caller guarantees buffer is writable for buffer_size bytes (checked ≥ 22).
            std::ptr::write_bytes(buf, 0, 22);

            let file_size = meta.len() as i64;
            // Round allocation size up to the nearest 4 KiB cluster.
            let alloc_size = ((file_size + 4095) / 4096) * 4096;
            let nlinks = meta.nlink() as u32;
            let is_dir = meta.is_dir();

            // SAFETY: offsets are within the 22-byte buffer.
            std::ptr::write_unaligned(buf.add(0).cast::<i64>(), alloc_size); // AllocationSize
            std::ptr::write_unaligned(buf.add(8).cast::<i64>(), file_size); // EndOfFile
            std::ptr::write_unaligned(buf.add(16).cast::<u32>(), nlinks); // NumberOfLinks
            *buf.add(20) = 0u8; // DeletePending: always FALSE
            *buf.add(21) = u8::from(is_dir); // Directory
            1 // TRUE
        }
        _ => {
            kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
            0 // FALSE
        }
    }
}

/// GetFileSizeEx - retrieves the size of the specified file
///
/// Looks up the file handle in the kernel32 file-handle registry and calls
/// `metadata().len()` to get the actual file size.
///
/// # Safety
/// When `file_size` is non-null, it must be a valid, writable pointer to an `i64`
/// where the file size will be stored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileSizeEx(
    file: *mut core::ffi::c_void,
    file_size: *mut i64,
) -> i32 {
    if file_size.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let handle_val = file as usize;
    let size_result = with_file_handles(|map| {
        map.get(&handle_val)
            .and_then(|entry| entry.file.metadata().ok())
            .map(|m| m.len() as i64)
    });
    if let Some(sz) = size_result {
        *file_size = sz;
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        0 // FALSE
    }
}

/// GetFinalPathNameByHandleW - retrieves the final path for the specified file
///
/// Reads the `/proc/self/fd/<fd>` symlink to obtain the actual filesystem path
/// for the file handle, then converts it to a null-terminated UTF-16 string.
///
/// Returns the number of characters written (excluding the null terminator)
/// on success, or 0 on failure.  When `file_path` is null or the buffer is
/// too small, returns the required buffer length (including the null terminator)
/// and sets `ERROR_INSUFFICIENT_BUFFER`.
///
/// # Safety
/// When `file_path` is non-null it must be writable for `file_path_size` `u16`
/// elements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFinalPathNameByHandleW(
    file: *mut core::ffi::c_void,
    file_path: *mut u16,
    file_path_size: u32,
    _flags: u32,
) -> u32 {
    let handle_val = file as usize;
    let raw_fd = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.as_raw_fd()));
    let Some(fd) = raw_fd else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };

    let proc_path = std::format!("/proc/self/fd/{fd}");
    let Ok(real_path) = std::fs::read_link(&proc_path) else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        return 0;
    };

    let path_str = real_path.to_string_lossy();
    // Build a null-terminated UTF-16 representation of the path.
    let wide: Vec<u16> = path_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .collect();
    let needed = wide.len() as u32; // includes the null terminator

    if file_path.is_null() || file_path_size < needed {
        kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return needed; // callers use this to size the buffer
    }

    for (i, &ch) in wide.iter().enumerate() {
        // SAFETY: Caller guarantees file_path is writable for file_path_size u16 elements,
        // and we've checked file_path_size >= needed.
        *file_path.add(i) = ch;
    }

    needed - 1 // return count of chars written, excluding the null terminator
}

/// GetOverlappedResult - retrieves the result of an overlapped operation
///
/// Reads the `Internal` (status code) and `InternalHigh` (bytes transferred)
/// fields from the supplied OVERLAPPED structure, which are populated by
/// `ReadFileEx`, `WriteFileEx`, `ReadFile` (when IOCP-associated), and
/// `WriteFile` (when IOCP-associated).  The `wait` parameter is accepted but
/// ignored; all I/O completions recorded in the OVERLAPPED structure are
/// already finished by the time these functions return.
///
/// Returns TRUE if `Internal == 0` (STATUS_SUCCESS), FALSE otherwise.
/// On failure sets the last error to the Windows error code stored in
/// `Internal`.
///
/// # Safety
/// `overlapped` must point to a readable Windows OVERLAPPED structure when
/// non-null.  `number_of_bytes_transferred`, if non-null, must be a valid
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOverlappedResult(
    _file: *mut core::ffi::c_void,
    overlapped: *mut core::ffi::c_void,
    number_of_bytes_transferred: *mut u32,
    _wait: i32,
) -> i32 {
    if overlapped.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let (status, bytes) = get_overlapped_result(overlapped.cast_const());
    if !number_of_bytes_transferred.is_null() {
        *number_of_bytes_transferred = u32::try_from(bytes).unwrap_or(u32::MAX);
    }
    if status == 0 {
        1 // TRUE - success
    } else {
        // Convert NTSTATUS to a Windows error code (best-effort: use the low
        // 16-bit facility/code, which for common I/O errors is a valid Win32 code).
        let win_err = u32::try_from(status).map(|s| s & 0xFFFF).unwrap_or(87); // ERROR_INVALID_PARAMETER as fallback
        kernel32_SetLastError(win_err);
        0 // FALSE
    }
}

/// GetProcessId - retrieves the process identifier of the specified process
///
/// When `process` is the current-process pseudo-handle (`-1`) or any other
/// handle, returns the actual PID of this (Linux) process via
/// `std::process::id()`.
///
/// # Safety
/// `process` is accepted as an opaque handle value and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessId(_process: *mut core::ffi::c_void) -> u32 {
    std::process::id()
}

/// GetSystemDirectoryW - returns the Windows system directory path
///
/// Returns `C:\Windows\System32` as the system directory.  When `buffer` is
/// null or too small, the required size (including the null terminator) is
/// returned so callers can retry with the correct buffer size.
///
/// # Safety
/// When `buffer` is non-null, it must be a valid writable buffer of at least
/// `size` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    // "C:\Windows\System32" encoded as UTF-16 (null-terminated)
    let path: &[u16] = &[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        u16::from(b'W'),
        u16::from(b'i'),
        u16::from(b'n'),
        u16::from(b'd'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b's'),
        u16::from(b'\\'),
        u16::from(b'S'),
        u16::from(b'y'),
        u16::from(b's'),
        u16::from(b't'),
        u16::from(b'e'),
        u16::from(b'm'),
        u16::from(b'3'),
        u16::from(b'2'),
        0u16,
    ];
    let required = path.len() as u32; // includes null terminator
    if buffer.is_null() || size < required {
        return required;
    }
    for (i, &ch) in path.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    (path.len() - 1) as u32 // characters written, excluding null terminator
}

/// GetTempPathW - retrieves the path of the directory designated for temporary files
///
/// Returns the path reported by `std::env::temp_dir()` (typically `/tmp` on
/// Linux) as a null-terminated UTF-16 string with a trailing directory
/// separator.
///
/// If `buffer` is null or `buffer_length` is too small, returns the required
/// buffer size (in UTF-16 code units, including the null terminator); otherwise
/// copies the path and returns the length excluding the null terminator.
///
/// # Safety
/// `buffer`, if non-null, must point to a writable area of at least
/// `buffer_length` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTempPathW(buffer_length: u32, buffer: *mut u16) -> u32 {
    let temp_dir = std::env::temp_dir();
    let mut dir_str = temp_dir.to_string_lossy().into_owned();
    if !dir_str.ends_with('/') {
        dir_str.push('/');
    }
    let mut utf16: Vec<u16> = dir_str.encode_utf16().collect();
    utf16.push(0); // null terminator

    let required = utf16.len() as u32;
    if buffer.is_null() || buffer_length < required {
        return required;
    }

    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }

    (utf16.len() - 1) as u32 // length without null terminator
}

/// GetTempPathA - retrieves the path of the directory for temporary files (ANSI version)
///
/// Returns the same path as `GetTempPathW` encoded as a null-terminated ANSI
/// (UTF-8) string.  The trailing directory separator is included.
///
/// If `buffer` is null or `buffer_length` is too small, returns the required
/// buffer size (in bytes, including the null terminator); otherwise copies
/// the path and returns the length excluding the null terminator.
///
/// # Safety
/// `buffer`, if non-null, must point to a writable area of at least
/// `buffer_length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTempPathA(buffer_length: u32, buffer: *mut u8) -> u32 {
    let temp_dir = std::env::temp_dir();
    let mut dir_str = temp_dir.to_string_lossy().into_owned();
    if !dir_str.ends_with('/') {
        dir_str.push('/');
    }
    let bytes = dir_str.as_bytes();
    let required = bytes.len() as u32 + 1; // +1 for null terminator
    if buffer.is_null() || buffer_length < required {
        return required;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len());
    *buffer.add(bytes.len()) = 0; // null terminator
    bytes.len() as u32 // length without null terminator
}

/// GetWindowsDirectoryW - returns the Windows directory path
///
/// Returns `C:\Windows` as the Windows directory.  When `buffer` is null or
/// too small, the required size (including the null terminator) is returned.
///
/// # Safety
/// When `buffer` is non-null, it must be a valid writable buffer of at least
/// `size` UTF-16 code units.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetWindowsDirectoryW(buffer: *mut u16, size: u32) -> u32 {
    // "C:\Windows" encoded as UTF-16 (null-terminated)
    let path: &[u16] = &[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        u16::from(b'W'),
        u16::from(b'i'),
        u16::from(b'n'),
        u16::from(b'd'),
        u16::from(b'o'),
        u16::from(b'w'),
        u16::from(b's'),
        0u16,
    ];
    let required = path.len() as u32; // includes null terminator
    if buffer.is_null() || size < required {
        return required;
    }
    for (i, &ch) in path.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    (path.len() - 1) as u32 // characters written, excluding null terminator
}

/// InitOnceBeginInitialize - begin a one-time initialisation
///
/// This implementation always reports that initialisation is already complete
/// (`*pending = FALSE`, returns TRUE).  In the single-process model used here
/// there is no concurrent initialisation, so treating every `INIT_ONCE` object
/// as already-initialised is the correct simplification.
///
/// # Safety
/// `pending` must be either null or a valid pointer to an `i32`.
/// `context` is ignored and need not be valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceBeginInitialize(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    pending: *mut i32,
    _context: *mut *mut core::ffi::c_void,
) -> i32 {
    // Set pending to FALSE, indicating initialization is complete
    if !pending.is_null() {
        *pending = 0;
    }
    1 // TRUE
}

/// InitOnceComplete - complete a one-time initialisation
///
/// Because `InitOnceBeginInitialize` always reports initialisation as already
/// done, this function is never called in practice.  Returning TRUE is the
/// correct no-op.
///
/// # Safety
/// This function never dereferences any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitOnceComplete(
    _init_once: *mut core::ffi::c_void,
    _flags: u32,
    _context: *mut core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// InitializeProcThreadAttributeList - initialises a process/thread attribute list
///
/// When `attribute_list` is null the function writes the required buffer size
/// to `*size` and returns FALSE with `ERROR_INSUFFICIENT_BUFFER`, which is the
/// standard Windows pattern for querying the required size.
///
/// When `attribute_list` is non-null the function zero-initialises the buffer
/// (as a minimal marker) and returns TRUE.  Because we do not implement
/// process creation, the attribute values are never consumed.
///
/// # Safety
/// When `attribute_list` is non-null it must be writable for `*size` bytes.
/// When `size` is non-null it must be a valid readable/writable `usize` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeProcThreadAttributeList(
    attribute_list: *mut core::ffi::c_void,
    _attribute_count: u32,
    _flags: u32,
    size: *mut usize,
) -> i32 {
    // Minimal opaque size for our attribute list placeholder.
    const MIN_ATTR_LIST_SIZE: usize = 64;

    if attribute_list.is_null() {
        // Caller is querying the required size.
        if !size.is_null() {
            *size = MIN_ATTR_LIST_SIZE;
        }
        kernel32_SetLastError(122); // ERROR_INSUFFICIENT_BUFFER
        return 0; // FALSE
    }

    // At this point, attribute_list is non-null. According to the Windows API
    // contract, size must also be non-null; otherwise this is an invalid call.
    if size.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }

    // Caller provided a buffer; zero-initialise it so it is in a defined state.
    let buf_size = (*size).max(MIN_ATTR_LIST_SIZE);
    // SAFETY: attribute_list is non-null (checked above); caller is required by
    // the Windows API contract to provide a buffer of at least *size bytes.
    std::ptr::write_bytes(attribute_list.cast::<u8>(), 0, buf_size);
    1 // TRUE
}

/// LockFileEx - locks a region of a file for shared or exclusive access
///
/// Locks a byte-range region of the file associated with `file`.  The lock
/// type is determined by `flags`:
/// - `LOCKFILE_EXCLUSIVE_LOCK` (0x2): exclusive (write) lock; otherwise shared (read)
/// - `LOCKFILE_FAIL_IMMEDIATELY` (0x1): return immediately if the lock cannot be acquired
///
/// The byte-range parameters and the `overlapped` pointer are accepted but
/// ignored because `flock(2)` locks the whole file.
///
/// Returns TRUE (1) on success, FALSE (0) on failure. On failure, the last
/// error is set to:
/// - `ERROR_INVALID_HANDLE` (6) if `file` is not a valid file handle.
/// - `ERROR_LOCK_VIOLATION` (33) if the underlying `flock(2)` call fails for
///   any reason (including contention when the requested lock cannot be
///   obtained).
///
/// # Safety
/// `file` must be a valid handle previously returned by `CreateFileW`, or
/// `INVALID_HANDLE_VALUE`.  `overlapped` is accepted but not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LockFileEx(
    file: *mut core::ffi::c_void,
    flags: u32,
    _reserved: u32,
    _number_of_bytes_to_lock_low: u32,
    _number_of_bytes_to_lock_high: u32,
    _overlapped: *mut core::ffi::c_void,
) -> i32 {
    use std::os::unix::io::AsRawFd as _;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    let handle_val = file as usize;
    let fd = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.as_raw_fd()));
    let Some(fd) = fd else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let mut lock_op = if flags & LOCKFILE_EXCLUSIVE_LOCK != 0 {
        libc::LOCK_EX
    } else {
        libc::LOCK_SH
    };
    if flags & LOCKFILE_FAIL_IMMEDIATELY != 0 {
        lock_op |= libc::LOCK_NB;
    }
    // SAFETY: fd is a valid file descriptor obtained from the handle registry.
    let ret = unsafe { libc::flock(fd, lock_op) };
    if ret == 0 {
        1 // TRUE
    } else {
        kernel32_SetLastError(33); // ERROR_LOCK_VIOLATION
        0
    }
}

/// MapViewOfFile - maps a view of a file mapping into the calling process's address space
///
/// Looks up the file mapping handle created by `CreateFileMappingA`, calls
/// `mmap(2)` with the appropriate protection derived from `desired_access`,
/// and registers the returned base address in `MAPPED_VIEWS` so that
/// `UnmapViewOfFile` can release it.
///
/// # Safety
/// `file_mapping_object` must be a handle returned by `CreateFileMappingA`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MapViewOfFile(
    file_mapping_object: *mut core::ffi::c_void,
    desired_access: u32,
    file_offset_high: u32,
    file_offset_low: u32,
    number_of_bytes_to_map: usize,
) -> *mut core::ffi::c_void {
    let mapping_handle = file_mapping_object as usize;
    let entry = with_file_mapping_handles(|map| {
        map.get(&mapping_handle)
            .map(|e| (e.raw_fd, e.size, e.protect))
    });
    let Some((raw_fd, mapping_size, protect)) = entry else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return core::ptr::null_mut();
    };

    let file_offset = ((i64::from(file_offset_high) << 32) | i64::from(file_offset_low)).max(0);

    // Determine the size to map.
    let actual_size = if number_of_bytes_to_map > 0 {
        number_of_bytes_to_map
    } else if mapping_size > 0 {
        mapping_size as usize
    } else {
        // Anonymous mapping without explicit size: default to 64 KiB.
        0x1_0000
    };

    // Windows PAGE_* protection constants:
    //   PAGE_READONLY           = 0x02
    //   PAGE_READWRITE          = 0x04
    //   PAGE_WRITECOPY          = 0x08
    //   PAGE_EXECUTE_READ       = 0x20
    //   PAGE_EXECUTE_READWRITE  = 0x40
    // FILE_MAP_WRITE (desired_access bit 2) overrides to read+write.
    let prot = if desired_access & 0x04 != 0 || protect == 4 || protect == 8 {
        libc::PROT_READ | libc::PROT_WRITE
    } else if desired_access & 0x20 != 0 || protect == 0x20 {
        libc::PROT_READ | libc::PROT_EXEC
    } else if protect == 0x40 {
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC
    } else {
        libc::PROT_READ
    };

    let (flags, fd) = if raw_fd == -1 {
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1i32)
    } else {
        (libc::MAP_SHARED, raw_fd)
    };

    // SAFETY: mmap parameters are valid; we own the fd (or -1 for anonymous).
    let ptr = libc::mmap(
        core::ptr::null_mut(),
        actual_size,
        prot,
        flags,
        fd,
        file_offset,
    );

    if ptr == libc::MAP_FAILED {
        kernel32_SetLastError(8); // ERROR_NOT_ENOUGH_MEMORY
        return core::ptr::null_mut();
    }

    with_mapped_views(|map| {
        map.insert(ptr as usize, actual_size);
    });
    ptr
}

/// Module32FirstW - retrieves information about the first module in a snapshot
///
/// Returns FALSE because `CreateToolhelp32Snapshot` always returns
/// `INVALID_HANDLE_VALUE` in this sandboxed environment, so no valid snapshot
/// handle can reach this function.  Sets `ERROR_NO_MORE_FILES` (18).
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32FirstW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    kernel32_SetLastError(18); // ERROR_NO_MORE_FILES
    0 // FALSE
}

/// Module32NextW - retrieves information about the next module in a snapshot
///
/// Returns FALSE because `CreateToolhelp32Snapshot` always returns
/// `INVALID_HANDLE_VALUE` in this sandboxed environment, so no valid snapshot
/// handle can reach this function.  Sets `ERROR_NO_MORE_FILES` (18).
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_Module32NextW(
    _snapshot: *mut core::ffi::c_void,
    _module_entry: *mut core::ffi::c_void,
) -> i32 {
    kernel32_SetLastError(18); // ERROR_NO_MORE_FILES
    0 // FALSE
}

/// MoveFileExW - renames or moves a file or directory
///
/// Translates both path arguments with `wide_path_to_linux` then calls
/// `std::fs::rename`.  The `flags` parameter is accepted but ignored.
///
/// # Safety
/// `existing_file_name` and `new_file_name` must be valid null-terminated UTF-16
/// strings when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_MoveFileExW(
    existing_file_name: *const u16,
    new_file_name: *const u16,
    _flags: u32,
) -> i32 {
    if existing_file_name.is_null() || new_file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let src = wide_path_to_linux(existing_file_name);
    let dst = wide_path_to_linux(new_file_name);
    match std::fs::rename(&src, &dst) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::AlreadyExists => 183,  // ERROR_ALREADY_EXISTS
                _ => 2,                                    // ERROR_FILE_NOT_FOUND (generic)
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// ReadFileEx - reads from a file using an overlapped (APC-based) async operation
///
/// Performs a synchronous read and then queues an APC (Asynchronous Procedure
/// Call) on the current thread's APC queue.  The completion routine is invoked
/// the next time the thread enters an alertable wait via `SleepEx` or
/// `WaitForSingleObjectEx` with `alertable=TRUE`.
///
/// Returns TRUE on success (the operation was initiated and a completion
/// will be delivered), FALSE on error.
///
/// # Safety
/// `file` must be a valid handle.  `buffer` must be writable for at least
/// `number_of_bytes_to_read` bytes.  `overlapped` must point to a writable
/// OVERLAPPED structure.  `completion_routine` must be a valid
/// `LPOVERLAPPED_COMPLETION_ROUTINE` when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadFileEx(
    file: *mut core::ffi::c_void,
    buffer: *mut u8,
    number_of_bytes_to_read: u32,
    overlapped: *mut core::ffi::c_void,
    completion_routine: *mut core::ffi::c_void,
) -> i32 {
    if buffer.is_null() || overlapped.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let handle_val = file as usize;
    let count = number_of_bytes_to_read as usize;
    // SAFETY: Caller guarantees buffer is valid for `count` bytes.
    let slice = std::slice::from_raw_parts_mut(buffer, count);

    let bytes_read = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.read(slice).ok()
        } else {
            None
        }
    });

    let Some(n) = bytes_read else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let error_code: u32 = 0;
    let bytes = u32::try_from(n).unwrap_or(u32::MAX);

    // Record the result in the OVERLAPPED structure.
    set_overlapped_result(overlapped, u64::from(error_code), u64::from(bytes));

    // Queue an APC for the completion routine, if provided.
    if !completion_routine.is_null() {
        // SAFETY: The caller guarantees completion_routine is a valid
        // LPOVERLAPPED_COMPLETION_ROUTINE (win64 ABI).
        let callback: OverlappedCompletionRoutine = std::mem::transmute(completion_routine);
        APC_QUEUE.with(|q| {
            q.borrow_mut().push(ApcEntry {
                error_code,
                bytes_transferred: bytes,
                overlapped: overlapped as usize,
                callback,
            });
        });
    }

    1 // TRUE
}

/// RemoveDirectoryW - removes an existing empty directory
///
/// Translates the path with `wide_path_to_linux` then calls `std::fs::remove_dir`.
///
/// # Safety
/// `path_name` must be a valid null-terminated UTF-16 string when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_RemoveDirectoryW(path_name: *const u16) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path = wide_path_to_linux(path_name);
    match std::fs::remove_dir(&path) {
        Ok(()) => 1, // TRUE
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                // std::io::ErrorKind::DirectoryNotEmpty doesn't exist yet on stable Rust,
                // but POSIX ENOTEMPTY maps to `Other`.
                _ => {
                    // Check for ENOTEMPTY via the OS error code
                    if e.raw_os_error() == Some(libc::ENOTEMPTY) {
                        145 // ERROR_DIR_NOT_EMPTY
                    } else {
                        2 // ERROR_FILE_NOT_FOUND (generic)
                    }
                }
            };
            kernel32_SetLastError(code);
            0 // FALSE
        }
    }
}

/// SetCurrentDirectoryW - sets the current working directory
///
/// Returns 1 (TRUE) on success, 0 (FALSE) on failure.
///
/// # Safety
/// Caller must ensure path_name points to a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetCurrentDirectoryW(path_name: *const u16) -> i32 {
    if path_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    // Read UTF-16 string until null terminator
    let mut len = 0;
    while *path_name.add(len) != 0 {
        len += 1;
        // Safety check: prevent infinite loop
        if len > 32768 {
            // MAX_PATH is 260, but we allow more
            kernel32_SetLastError(206); // ERROR_FILENAME_EXCEED_RANGE
            return 0;
        }
    }

    // Convert to Rust string
    let slice = core::slice::from_raw_parts(path_name, len);
    let path_str = String::from_utf16_lossy(slice);

    // Try to set the current directory
    if std::env::set_current_dir(std::path::Path::new(path_str.as_str())).is_ok() {
        1 // TRUE - success
    } else {
        // Set last error to ERROR_FILE_NOT_FOUND (2)
        kernel32_SetLastError(2);
        0 // FALSE - failure
    }
}

/// SetFileAttributesW — sets the attributes of a file or directory.
///
/// Maps Windows `FILE_ATTRIBUTE_READONLY (0x1)` to the Linux permission model
/// by toggling only the **owner write bit** (`0o200`).  Group and other write
/// bits are left unchanged to avoid inadvertent permission side-effects.
/// Other attribute bits (hidden, system, archive, etc.) have no direct Linux
/// equivalent and are silently accepted so that programs that set them do not
/// fail.
///
/// Returns TRUE on success, FALSE on failure (sets last error).
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileAttributesW(
    file_name: *const u16,
    file_attributes: u32,
) -> i32 {
    use std::os::unix::fs::PermissionsExt as _;
    const FILE_ATTRIBUTE_READONLY: u32 = 0x0001;

    if file_name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let path_str = wide_path_to_linux(file_name);
    if path_str.is_empty() {
        // Empty path signals a sandbox escape — treat as access denied.
        kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
        return 0;
    }
    let path = std::path::Path::new(&path_str);
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mut perms = meta.permissions();
            let current_mode = perms.mode();
            if (file_attributes & FILE_ATTRIBUTE_READONLY) != 0 {
                // Clear only the owner write bit.  Group and other write bits
                // are not changed to avoid inadvertent permission side-effects.
                perms.set_mode(current_mode & !0o200);
            } else {
                // Restore only the owner write bit to avoid broadening access
                // beyond what the original mode allowed for group/other.
                perms.set_mode(current_mode | 0o200);
            }
            if let Ok(()) = std::fs::set_permissions(path, perms) {
                1 // TRUE
            } else {
                kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
                0
            }
        }
        Err(e) => {
            let win_err = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,                                    // ERROR_FILE_NOT_FOUND
            };
            kernel32_SetLastError(win_err);
            0
        }
    }
}

/// SetFileInformationByHandle - sets file information by file handle
///
/// Setting extended file information via information-class codes is not
/// supported in this sandboxed environment.  Returns FALSE and sets
/// `ERROR_NOT_SUPPORTED` (50).
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileInformationByHandle(
    _file: *mut core::ffi::c_void,
    _file_information_class: u32,
    _file_information: *mut core::ffi::c_void,
    _buffer_size: u32,
) -> i32 {
    kernel32_SetLastError(50); // ERROR_NOT_SUPPORTED
    0 // FALSE
}

/// SetFileTime - sets the date and time that a file was created, accessed, or modified
///
/// On Linux we have limited ability to set all three timestamps accurately via
/// `utimes`.  For simplicity this always returns TRUE (success) without
/// actually updating timestamps; programs that inspect file timestamps may
/// observe stale values.
///
/// # Safety
/// All pointer arguments are accepted but not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFileTime(
    _file: *mut core::ffi::c_void,
    _creation_time: *const core::ffi::c_void,
    _last_access_time: *const core::ffi::c_void,
    _last_write_time: *const core::ffi::c_void,
) -> i32 {
    1 // TRUE
}

/// SetHandleInformation - sets certain properties of an object handle
///
/// Handle inheritance and protections are not meaningful in our single-process
/// emulation environment, so this always returns TRUE (success).
///
/// # Safety
/// `object` is accepted as an opaque handle and is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetHandleInformation(
    _object: *mut core::ffi::c_void,
    _mask: u32,
    _flags: u32,
) -> i32 {
    1 // TRUE
}

/// UnlockFile - unlocks a region of an open file
///
/// Releases the `flock(2)` lock held by `LockFileEx` on this file.  The
/// byte-range parameters are accepted but ignored because `flock` operates
/// on the whole file.  Returns TRUE (1) on success, or FALSE (0) with
/// `ERROR_INVALID_HANDLE` (6) if the handle is not in the file registry, or
/// `ERROR_NOT_LOCKED` (158) if releasing the underlying `flock` lock fails.
///
/// # Safety
/// `file` must be a valid handle previously returned by `CreateFileW`, or
/// `INVALID_HANDLE_VALUE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnlockFile(
    file: *mut core::ffi::c_void,
    _offset_low: u32,
    _offset_high: u32,
    _number_of_bytes_to_unlock_low: u32,
    _number_of_bytes_to_unlock_high: u32,
) -> i32 {
    use std::os::unix::io::AsRawFd as _;
    let handle_val = file as usize;
    let fd = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.as_raw_fd()));
    let Some(fd) = fd else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    // SAFETY: fd is a valid file descriptor obtained from the handle registry.
    let ret = unsafe { libc::flock(fd, libc::LOCK_UN) };
    if ret == 0 {
        1
    } else {
        kernel32_SetLastError(158); // ERROR_NOT_LOCKED
        0
    }
}

/// UnmapViewOfFile - unmaps a mapped view of a file from the address space
///
/// Looks up `base_address` in the `MAPPED_VIEWS` registry that was populated
/// by `MapViewOfFile` and calls `munmap(2)` with the stored size.  If the
/// address is not in the registry (e.g. the caller passes an already-unmapped
/// pointer) the function still returns TRUE for compatibility with programs
/// that do not check the return value.
///
/// # Safety
/// `base_address` must be a pointer previously returned by `MapViewOfFile`,
/// or null (in which case the call is a no-op that returns TRUE).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UnmapViewOfFile(base_address: *const core::ffi::c_void) -> i32 {
    if base_address.is_null() {
        return 1; // TRUE — Windows docs say null is a no-op
    }
    let ptr_val = base_address as usize;
    if let Some(size) = with_mapped_views(|map| map.remove(&ptr_val)) {
        // SAFETY: base_address was previously returned by mmap (via MapViewOfFile)
        // and the size was recorded at that time.
        libc::munmap(base_address.cast_mut(), size);
    }
    1 // TRUE
}

/// UpdateProcThreadAttribute - update a process/thread attribute
///
/// Accepts the attribute without storing it, because `CreateProcessW` is not
/// yet implemented and the attribute list is never consumed.  Returns TRUE so
/// callers that chain multiple `UpdateProcThreadAttribute` calls can proceed.
///
/// # Safety
/// This function never dereferences any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_UpdateProcThreadAttribute(
    _attribute_list: *mut core::ffi::c_void,
    _flags: u32,
    _attribute: usize,
    _value: *mut core::ffi::c_void,
    _size: usize,
    _previous_value: *mut core::ffi::c_void,
    _return_size: *mut usize,
) -> i32 {
    1 // TRUE
}

/// WriteFileEx - writes to a file using an overlapped (APC-based) async operation
///
/// Performs a synchronous write and then queues an APC (Asynchronous Procedure
/// Call) on the current thread's APC queue.  The completion routine is invoked
/// the next time the thread enters an alertable wait via `SleepEx` or
/// `WaitForSingleObjectEx` with `alertable=TRUE`.
///
/// Returns TRUE on success (the operation was initiated and a completion
/// will be delivered), FALSE on error.
///
/// # Safety
/// `file` must be a valid handle.  `buffer` must be readable for at least
/// `number_of_bytes_to_write` bytes.  `overlapped` must point to a writable
/// OVERLAPPED structure.  `completion_routine` must be a valid
/// `LPOVERLAPPED_COMPLETION_ROUTINE` when non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteFileEx(
    file: *mut core::ffi::c_void,
    buffer: *const u8,
    number_of_bytes_to_write: u32,
    overlapped: *mut core::ffi::c_void,
    completion_routine: *mut core::ffi::c_void,
) -> i32 {
    if buffer.is_null() || overlapped.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let handle_val = file as usize;
    // SAFETY: Caller guarantees buffer is valid for `number_of_bytes_to_write` bytes.
    let data = std::slice::from_raw_parts(buffer, number_of_bytes_to_write as usize);

    let bytes_written = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&handle_val) {
            entry.file.write(data).ok()
        } else {
            None
        }
    });

    let Some(n) = bytes_written else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let error_code: u32 = 0;
    let bytes = u32::try_from(n).unwrap_or(u32::MAX);

    // Record the result in the OVERLAPPED structure.
    set_overlapped_result(overlapped, u64::from(error_code), u64::from(bytes));

    // Queue an APC for the completion routine, if provided.
    if !completion_routine.is_null() {
        // SAFETY: The caller guarantees completion_routine is a valid
        // LPOVERLAPPED_COMPLETION_ROUTINE (win64 ABI).
        let callback: OverlappedCompletionRoutine = std::mem::transmute(completion_routine);
        APC_QUEUE.with(|q| {
            q.borrow_mut().push(ApcEntry {
                error_code,
                bytes_transferred: bytes,
                overlapped: overlapped as usize,
                callback,
            });
        });
    }

    1 // TRUE
}

/// SetThreadStackGuarantee - sets the minimum stack size for the current thread
///
/// Stack size management is handled by the OS; this always returns TRUE
/// (success) without modifying the actual stack.
///
/// # Safety
/// `stack_size_in_bytes` is accepted as a pointer but not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetThreadStackGuarantee(_stack_size_in_bytes: *mut u32) -> i32 {
    1 // TRUE
}

/// SetWaitableTimer - activates the specified waitable timer
///
/// Waitable timers are not implemented (`CreateWaitableTimerExW` always
/// returns NULL), so no valid timer handle can be passed to this function.
/// Returns TRUE as a no-op for compatibility with programs that do not check
/// whether `CreateWaitableTimerExW` succeeded before calling this function.
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetWaitableTimer(
    _timer: *mut core::ffi::c_void,
    _due_time: *const i64,
    _period: i32,
    _completion_routine: *mut core::ffi::c_void,
    _arg_to_completion_routine: *mut core::ffi::c_void,
    _resume: i32,
) -> i32 {
    1 // TRUE - pretend success
}

/// SleepEx - suspends the current thread with optional alertable wait
///
/// Sleeps for `milliseconds` milliseconds.  When `alertable` is non-zero,
/// any pending APC callbacks queued by `ReadFileEx` or `WriteFileEx` are
/// executed before sleeping and `WAIT_IO_COMPLETION` (0xC0) is returned.
/// If `alertable` is zero, this behaves identically to `Sleep` and returns 0.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SleepEx(milliseconds: u32, alertable: i32) -> u32 {
    if alertable != 0 {
        // Drain the APC queue before sleeping.
        let had_apcs = drain_apc_queue();
        if had_apcs {
            // Remaining sleep is skipped when APCs are delivered, matching
            // Windows behaviour (SleepEx returns early).
            return 0xC0; // WAIT_IO_COMPLETION
        }
    }
    if milliseconds > 0 {
        thread::sleep(Duration::from_millis(u64::from(milliseconds)));
    }
    0
}

/// SwitchToThread - yields execution to another runnable thread
///
/// Calls `std::thread::yield_now()` to give the scheduler an opportunity to
/// run another thread.  Returns TRUE.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SwitchToThread() -> i32 {
    thread::yield_now();
    1 // TRUE
}

/// TerminateProcess - terminates the specified process and all of its threads
///
/// When called with the current-process pseudo-handle (-1 / 0xFFFFFFFFFFFFFFFF),
/// this immediately exits the process.
/// For handles returned by `CreateProcessW`, the child process is killed with
/// `SIGKILL` and its handle is removed from the registry.
///
/// # Safety
/// Calling this with the current-process pseudo-handle is safe: it exits immediately.
///
/// # Panics
/// Panics if an internal mutex protecting child-process state is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_TerminateProcess(
    process: *mut core::ffi::c_void,
    exit_code: u32,
) -> i32 {
    // -1 (0xFFFFFFFFFFFFFFFF) is the Windows pseudo-handle for the current process.
    if process as isize == -1 {
        std::process::exit(exit_code as i32);
    }

    let handle_val = process as usize;
    let proc_info = with_process_handles(|map| map.remove(&handle_val));
    if let Some(entry) = proc_info {
        let mut guard = entry.child.lock().unwrap();
        if let Some(ref mut child) = *guard {
            let _ = child.kill();
            let _ = child.wait();
        }
        *entry.exit_code.lock().unwrap() = Some(exit_code);
        return 1; // TRUE
    }

    0 // FALSE - unknown handle
}

/// WaitForMultipleObjects - waits until one or all of the specified objects are in the
/// signaled state or the time-out interval elapses.
///
/// For thread handles in the registry:
///   - `wait_all != 0`: joins every thread in order; returns WAIT_OBJECT_0 when all finish.
///   - `wait_all == 0`: polls all handles; returns WAIT_OBJECT_0 + i for the first to finish.
///
/// Handles not found in the thread registry are treated as already-signaled.
///
/// # Panics
/// Panics if a thread's exit-code mutex is poisoned.
///
/// # Safety
/// `handles` must point to an array of `count` valid HANDLE values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitForMultipleObjects(
    count: u32,
    handles: *const *mut core::ffi::c_void,
    wait_all: i32,
    milliseconds: u32,
) -> u32 {
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    if count == 0 || handles.is_null() {
        return WAIT_OBJECT_0;
    }

    // Collect handle values.
    let handle_vals: Vec<usize> = (0..count as usize)
        .map(|i| unsafe { *handles.add(i) as usize })
        .collect();

    if wait_all != 0 {
        // Wait for ALL objects: join each thread handle sequentially.
        let start = std::time::Instant::now();
        let timeout_opt = if milliseconds == u32::MAX {
            None
        } else {
            Some(Duration::from_millis(u64::from(milliseconds)))
        };

        for &hval in &handle_vals {
            let thread_entry = with_thread_handles(|map| {
                map.get_mut(&hval).map(|entry| {
                    let jh = entry.join_handle.take();
                    let ec = Arc::clone(&entry.exit_code);
                    (jh, ec)
                })
            });

            let Some((join_handle_opt, _)) = thread_entry else {
                // Also handle sync handles
                let sync_done = with_sync_handles(|map| map.contains_key(&hval));
                if sync_done {
                    let h = hval as *mut core::ffi::c_void;
                    let remaining_ms = match timeout_opt {
                        None => u32::MAX,
                        Some(timeout) => {
                            let elapsed = start.elapsed();
                            if elapsed >= timeout {
                                return WAIT_TIMEOUT;
                            }
                            timeout
                                .checked_sub(elapsed)
                                .unwrap()
                                .as_millis()
                                .min(u128::from(u32::MAX)) as u32
                        }
                    };
                    let r = kernel32_WaitForSingleObject(h, remaining_ms);
                    if r == WAIT_TIMEOUT {
                        return WAIT_TIMEOUT;
                    }
                }
                continue; // non-thread handle: treat as signaled
            };
            let Some(join_handle) = join_handle_opt else {
                continue; // already joined
            };

            match timeout_opt {
                None => {
                    let _ = join_handle.join();
                }
                Some(timeout) => loop {
                    if join_handle.is_finished() {
                        let _ = join_handle.join();
                        break;
                    }
                    if start.elapsed() >= timeout {
                        with_thread_handles(|map| {
                            if let Some(entry) = map.get_mut(&hval) {
                                entry.join_handle = Some(join_handle);
                            }
                        });
                        return WAIT_TIMEOUT;
                    }
                    thread::sleep(Duration::from_millis(1));
                },
            }
        }
        WAIT_OBJECT_0
    } else {
        // Wait for ANY object: poll all handles until one finishes.
        let start = std::time::Instant::now();
        let timeout_opt = if milliseconds == u32::MAX {
            None
        } else {
            Some(Duration::from_millis(u64::from(milliseconds)))
        };

        loop {
            for (i, &hval) in handle_vals.iter().enumerate() {
                let is_done = with_thread_handles(|map| {
                    if let Some(entry) = map.get(&hval) {
                        // Signaled if exit_code is set or join_handle is finished/gone.
                        entry.exit_code.lock().unwrap().is_some()
                            || entry
                                .join_handle
                                .as_ref()
                                .is_none_or(std::thread::JoinHandle::is_finished)
                    } else {
                        true // non-thread handle: treat as signaled
                    }
                });

                if is_done {
                    // Join the thread if possible.
                    with_thread_handles(|map| {
                        if let Some(entry) = map.get_mut(&hval)
                            && let Some(jh) = entry.join_handle.take()
                        {
                            let _ = jh.join();
                        }
                    });
                    return WAIT_OBJECT_0 + i as u32;
                }
                // Check sync handles
                let sync_signaled = with_sync_handles(|map| map.contains_key(&hval));
                if sync_signaled {
                    let h = hval as *mut core::ffi::c_void;
                    let r = kernel32_WaitForSingleObject(h, 0);
                    if r == WAIT_OBJECT_0 {
                        return WAIT_OBJECT_0 + i as u32;
                    }
                }
            }

            if let Some(timeout) = timeout_opt
                && start.elapsed() >= timeout
            {
                return WAIT_TIMEOUT;
            }
            thread::sleep(Duration::from_millis(1));
        }
    }
}

/// ExitProcess - terminates the calling process and all its threads
///
/// # Safety
/// This function terminates the process immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ExitProcess(exit_code: u32) {
    std::process::exit(exit_code as i32);
}

/// GetCurrentProcess - returns a pseudo-handle for the current process
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentProcess() -> *mut core::ffi::c_void {
    // Windows returns -1 (0xFFFFFFFFFFFFFFFF) as the pseudo-handle for the current process
    -1_i64 as usize as *mut core::ffi::c_void
}

/// GetCurrentThread - returns a pseudo-handle for the current thread
///
/// # Safety
/// This function is safe to call. It returns a constant pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCurrentThread() -> *mut core::ffi::c_void {
    // Windows returns -2 (0xFFFFFFFFFFFFFFFE) as the pseudo-handle for the current thread
    -2_i64 as usize as *mut core::ffi::c_void
}

/// GetModuleHandleA - retrieves the module handle for the specified module (ANSI version)
///
/// When `module_name` is null, returns the base address of the main executable
/// (`0x400000`).  For named DLLs, looks up the handle in the dynamic-export
/// registry populated by `register_dynamic_exports`.
///
/// # Safety
/// `module_name` must be a valid null-terminated ANSI string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleHandleA(
    module_name: *const u8,
) -> *mut core::ffi::c_void {
    if module_name.is_null() {
        return 0x400000_usize as *mut core::ffi::c_void;
    }
    // SAFETY: caller guarantees module_name is a valid null-terminated C string.
    let name = std::ffi::CStr::from_ptr(module_name.cast::<i8>()).to_string_lossy();
    let upper = dll_basename(name.as_ref()).to_uppercase();
    let handle = with_dll_handles(|reg| reg.by_name.get(&upper).copied());
    if let Some(h) = handle {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(126); // ERROR_MOD_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// GetModuleFileNameW — retrieves the fully qualified path for the executable
/// that contains the specified module.
///
/// When `module` is null (i.e. the main executable), reads the path from
/// `/proc/self/exe` and returns it as a UTF-16 string in `filename`.
///
/// Non-null module handles refer to loaded DLLs; those are currently
/// unimplemented and the function returns 0 with `ERROR_GEN_FAILURE`.
///
/// On success, returns the number of UTF-16 characters written, excluding the
/// null terminator.
///
/// If `filename` is null or `size` is 0 or too small to hold the full path,
/// returns the required buffer length (in UTF-16 code units, including the
/// null terminator) and sets the last error to `ERROR_MORE_DATA`.  Note: real
/// Windows `GetModuleFileNameW` truncates the output and returns `nSize` when
/// the buffer is too small; this shim instead follows `GetEnvironmentVariableW`
/// semantics (returns required length, sets `ERROR_MORE_DATA`) to simplify
/// callers.
///
/// On other failures returns 0 and sets an appropriate Windows error code.
///
/// # Safety
/// `filename` must point to a valid buffer of at least `size` `u16` elements,
/// or be null.  `size` of 0 is treated as a null buffer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetModuleFileNameW(
    module: *mut core::ffi::c_void,
    filename: *mut u16,
    size: u32,
) -> u32 {
    // Only handle the "current executable" case (module == NULL).
    if !module.is_null() {
        kernel32_SetLastError(31); // ERROR_GEN_FAILURE - DLL handle not tracked
        return 0;
    }
    let exe_path = match std::fs::read_link("/proc/self/exe") {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => {
            let win_err = match e.kind() {
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                std::io::ErrorKind::NotFound => 2,         // ERROR_FILE_NOT_FOUND
                _ => 31,                                   // ERROR_GEN_FAILURE
            };
            kernel32_SetLastError(win_err);
            return 0;
        }
    };
    // SAFETY: filename and size are validated by copy_utf8_to_wide.
    copy_utf8_to_wide(&exe_path, filename, size)
}

/// Windows SYSTEM_INFO structure (x86_64 layout).
///
/// Matches the Windows API `SYSTEM_INFO` struct at
/// <https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info>.
/// Field names follow Windows naming conventions. Pointer-sized fields use `u64`
/// to match the fixed x86_64 Windows ABI layout (always 8 bytes).
#[repr(C)]
struct SystemInfo {
    w_processor_architecture: u16,
    w_reserved: u16,
    dw_page_size: u32,
    lp_minimum_application_address: u64,
    lp_maximum_application_address: u64,
    dw_active_processor_mask: u64,
    dw_number_of_processors: u32,
    dw_processor_type: u32,
    dw_allocation_granularity: u32,
    w_processor_level: u16,
    w_processor_revision: u16,
}

/// GetSystemInfo - retrieves information about the current system
///
/// # Safety
/// Caller must ensure `system_info` points to a valid buffer of at least
/// `core::mem::size_of::<SystemInfo>()` bytes when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemInfo(system_info: *mut u8) {
    if system_info.is_null() {
        return;
    }
    let info = SystemInfo {
        w_processor_architecture: 9, // PROCESSOR_ARCHITECTURE_AMD64
        w_reserved: 0,
        dw_page_size: 4096,
        lp_minimum_application_address: 0x10000,
        lp_maximum_application_address: 0x7FFF_FFFE_FFFF,
        dw_active_processor_mask: 1,
        dw_number_of_processors: 1,
        dw_processor_type: 8664, // PROCESSOR_AMD_X8664
        dw_allocation_granularity: 65536,
        w_processor_level: 6,
        w_processor_revision: 0,
    };
    // SAFETY: Caller guarantees system_info points to a valid buffer of sufficient size.
    core::ptr::copy_nonoverlapping(
        (&raw const info).cast::<u8>(),
        system_info,
        core::mem::size_of::<SystemInfo>(),
    );
}

/// GetConsoleMode - retrieves the current input mode of a console's input buffer
///
/// # Safety
/// Caller must ensure `mode` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleMode(
    _console_handle: *mut core::ffi::c_void,
    mode: *mut u32,
) -> i32 {
    if !mode.is_null() {
        // SAFETY: Caller guarantees mode is valid and non-null (checked above).
        *mode = 3; // ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT
    }
    1 // TRUE - success
}

/// GetConsoleOutputCP - retrieves the output code page used by the console
///
/// # Safety
/// This function is safe to call. It returns a constant value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleOutputCP() -> u32 {
    65001 // UTF-8
}

/// ReadConsoleW - reads character input from the console input buffer (wide version)
///
/// # Safety
/// Caller must ensure `chars_read` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadConsoleW(
    _console_input: *mut core::ffi::c_void,
    _buffer: *mut u16,
    _chars_to_read: u32,
    chars_read: *mut u32,
    _input_control: *mut core::ffi::c_void,
) -> i32 {
    if !chars_read.is_null() {
        // SAFETY: Caller guarantees chars_read is valid and non-null (checked above).
        *chars_read = 0;
    }
    1 // TRUE - success (no input available)
}

/// GetEnvironmentVariableW - retrieves the value of an environment variable (wide version)
///
/// Reads the variable from the process environment using the C library `getenv`.
/// The name is converted from UTF-16 to UTF-8 for the lookup, and the value is
/// returned as UTF-16.
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
/// `buffer` must point to a writable array of at least `size` `u16` elements, or be null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetEnvironmentVariableW(
    name: *const u16,
    buffer: *mut u16,
    size: u32,
) -> u32 {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let name_str = wide_str_to_string(name);
    let Ok(c_name) = CString::new(name_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    // SAFETY: c_name is a valid C string; getenv returns a pointer owned by the OS.
    let value_ptr = libc::getenv(c_name.as_ptr());
    if value_ptr.is_null() {
        kernel32_SetLastError(203); // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    // SAFETY: getenv returns a valid null-terminated C string.
    let env_value = std::ffi::CStr::from_ptr(value_ptr).to_string_lossy();
    // copy_utf8_to_wide follows Windows GetEnvironmentVariableW semantics:
    // - if buffer is null or too small: returns required size (including null terminator)
    // - if buffer is large enough: returns characters written (excluding null terminator)
    copy_utf8_to_wide(&env_value, buffer, size)
}

/// SetEnvironmentVariableW - sets the value of an environment variable (wide version)
///
/// When `value` is null the variable is removed.  Uses `setenv`/`unsetenv` from libc.
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
/// `value` must be a valid null-terminated UTF-16 string or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEnvironmentVariableW(
    name: *const u16,
    value: *const u16,
) -> i32 {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let name_str = wide_str_to_string(name);
    let Ok(c_name) = CString::new(name_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    if value.is_null() {
        // Delete the variable (Windows: SetEnvironmentVariable(name, NULL) removes it)
        // SAFETY: c_name is a valid C string.
        libc::unsetenv(c_name.as_ptr());
        return 1; // TRUE
    }
    let value_str = wide_str_to_string(value);
    let Ok(c_value) = CString::new(value_str.as_str()) else {
        kernel32_SetLastError(87);
        return 0;
    };
    // SAFETY: c_name and c_value are valid C strings; overwrite=1 replaces existing value.
    let result = libc::setenv(c_name.as_ptr(), c_value.as_ptr(), 1);
    if result == 0 {
        1 // TRUE
    } else {
        kernel32_SetLastError(13); // ERROR_INVALID_DATA
        0 // FALSE
    }
}

/// VirtualProtect - changes the protection on a region of committed pages
///
/// # Safety
/// Caller must ensure `old_protect` points to a valid u32 when it is non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualProtect(
    _address: *mut core::ffi::c_void,
    _size: usize,
    _new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    if !old_protect.is_null() {
        // SAFETY: Caller guarantees old_protect is valid and non-null (checked above).
        *old_protect = 0x40; // PAGE_EXECUTE_READWRITE
    }
    1 // TRUE - success
}

/// VirtualQuery - retrieves information about a range of pages in the virtual
/// address space of the calling process.
///
/// Fills a `MEMORY_BASIC_INFORMATION` structure (48 bytes on 64-bit Windows)
/// by parsing `/proc/self/maps` to find the region that contains `address`.
///
/// The 64-bit layout written into `buffer`:
/// - `[0..8]`   BaseAddress (page-aligned start of the region)
/// - `[8..16]`  AllocationBase (same as BaseAddress for private/anonymous maps)
/// - `[16..20]` AllocationProtect (Windows `PAGE_*` flags derived from the
///   current Linux permission bits; `/proc/self/maps` does not record the
///   original allocation protection, so this equals `Protect`)
/// - `[20..24]` padding (written as 0)
/// - `[24..32]` RegionSize
/// - `[32..36]` State (`MEM_COMMIT = 0x1000` if mapped, `MEM_FREE = 0x10000`
///   if no mapping was found)
/// - `[36..40]` Protect (current Windows `PAGE_*` flags derived from the Linux
///   `r`/`w`/`x` permission bits; equals `AllocationProtect` since the
///   original allocation protection is not tracked)
/// - `[40..44]` Type (`MEM_PRIVATE = 0x20000` for anonymous; `MEM_MAPPED =
///   0x40000` for file-backed; `MEM_IMAGE = 0x1000000` for the executable
///   image)
/// - `[44..48]` padding (written as 0)
///
/// **Limitation:** `AllocationProtect` and `Protect` are always identical because
/// `/proc/self/maps` only exposes the *current* protection; the original protection
/// at allocation time is not recorded.
///
/// Returns the number of bytes written on success (48), or 0 on failure.
///
/// # Safety
/// `buffer` must be non-null and point to at least `length` writable bytes.
/// `address` is only used as a lookup key and is never dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualQuery(
    address: *const core::ffi::c_void,
    buffer: *mut u8,
    length: usize,
) -> usize {
    // The structure we write is 48 bytes; bail if the caller's buffer is too small.
    const MBI_SIZE: usize = 48;
    // Windows PAGE_* protection constants
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_READONLY: u32 = 0x02;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE: u32 = 0x10;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    // Windows memory-type constants
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_FREE: u32 = 0x10000;
    const MEM_PRIVATE: u32 = 0x20000;
    const MEM_MAPPED: u32 = 0x40000;
    const MEM_IMAGE: u32 = 0x100_0000;

    if buffer.is_null() || length < MBI_SIZE {
        return 0;
    }

    let query_addr = address as usize;

    // Parse /proc/self/maps to locate the region.
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return 0;
    };

    // Each line: "start-end perms offset dev inode [pathname]"
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else {
            continue;
        };
        let Some((start_str, end_str)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start_str, 16),
            usize::from_str_radix(end_str, 16),
        ) else {
            continue;
        };
        if query_addr < start || query_addr >= end {
            continue;
        }

        // Found the region — decode permission flags.
        let perms = parts.next().unwrap_or("----");
        let readable = perms.as_bytes().first().copied() == Some(b'r');
        let writable = perms.as_bytes().get(1).copied() == Some(b'w');
        let executable = perms.as_bytes().get(2).copied() == Some(b'x');

        let protect: u32 = match (readable, writable, executable) {
            (false, _, true) => PAGE_EXECUTE,
            (true, false, true) => PAGE_EXECUTE_READ,
            (true, true, true) => PAGE_EXECUTE_READWRITE,
            (true, false, false) => PAGE_READONLY,
            (true, true, false) => PAGE_READWRITE,
            _ => PAGE_NOACCESS,
        };

        // Determine memory type from the pathname field.
        // In /proc/self/maps:
        //   - Empty pathname or special tokens like "[heap]"/"[stack]"/"[vdso]" →
        //     anonymous/private memory → MEM_PRIVATE (regardless of execute bit)
        //   - Pathname of a shared object (contains ".so" followed by nothing or
        //     a version suffix like ".so.6") → MEM_IMAGE (executable image)
        //   - Any other file-backed mapping → MEM_MAPPED
        let pathname = parts.nth(3).unwrap_or(""); // skip offset, dev, inode
        let mem_type: u32 = if pathname.is_empty() || pathname.starts_with('[') {
            MEM_PRIVATE // anonymous or special region ([heap], [stack], [vdso], …)
        } else if pathname.contains(".so") {
            // Shared objects may appear as "libfoo.so" or "libfoo.so.6".
            MEM_IMAGE
        } else {
            MEM_MAPPED
        };

        let region_size = (end - start) as u64;
        let base_addr = start as u64;

        // Write the MEMORY_BASIC_INFORMATION fields using unaligned writes.
        // SAFETY: We checked buffer is non-null and length >= MBI_SIZE above.
        let p = buffer;
        // BaseAddress [0..8]
        std::ptr::write_unaligned(p.add(0).cast::<u64>(), base_addr);
        // AllocationBase [8..16]
        std::ptr::write_unaligned(p.add(8).cast::<u64>(), base_addr);
        // AllocationProtect [16..20]
        std::ptr::write_unaligned(p.add(16).cast::<u32>(), protect);
        // padding [20..24]
        std::ptr::write_unaligned(p.add(20).cast::<u32>(), 0u32);
        // RegionSize [24..32]
        std::ptr::write_unaligned(p.add(24).cast::<u64>(), region_size);
        // State [32..36]
        std::ptr::write_unaligned(p.add(32).cast::<u32>(), MEM_COMMIT);
        // Protect [36..40]
        std::ptr::write_unaligned(p.add(36).cast::<u32>(), protect);
        // Type [40..44]
        std::ptr::write_unaligned(p.add(40).cast::<u32>(), mem_type);
        // padding [44..48]
        std::ptr::write_unaligned(p.add(44).cast::<u32>(), 0u32);

        return MBI_SIZE;
    }

    // Address not found in any mapping — report as free.
    // BaseAddress: page-aligned address (query the OS for the actual page size).
    // SAFETY: sysconf is always safe to call with _SC_PAGESIZE.
    let raw_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size: usize = if raw_page_size <= 0 || raw_page_size > (1 << 30) {
        // Fallback to a sane default if sysconf fails or returns an absurd value.
        4096
    } else {
        raw_page_size as usize
    };
    let base_addr = (query_addr & !(page_size - 1)) as u64;
    let p = buffer;
    // SAFETY: We checked buffer is non-null and length >= MBI_SIZE above.
    std::ptr::write_unaligned(p.add(0).cast::<u64>(), base_addr);
    std::ptr::write_unaligned(p.add(8).cast::<u64>(), 0u64); // AllocationBase: 0 for free
    std::ptr::write_unaligned(p.add(16).cast::<u32>(), 0u32); // AllocationProtect
    std::ptr::write_unaligned(p.add(20).cast::<u32>(), 0u32); // padding
    std::ptr::write_unaligned(p.add(24).cast::<u64>(), page_size as u64); // RegionSize: one page
    std::ptr::write_unaligned(p.add(32).cast::<u32>(), MEM_FREE);
    std::ptr::write_unaligned(p.add(36).cast::<u32>(), PAGE_NOACCESS);
    std::ptr::write_unaligned(p.add(40).cast::<u32>(), 0u32); // Type: 0 for free
    std::ptr::write_unaligned(p.add(44).cast::<u32>(), 0u32); // padding

    MBI_SIZE
}

/// FreeLibrary - frees the loaded dynamic-link library module
///
/// In the Windows-on-Linux shim, DLLs are not loaded as shared objects; their
/// exports are resolved at PE-load time by the shim loader.  Unloading is a
/// no-op, and returning TRUE (success) is the correct response.
///
/// # Safety
/// This function never dereferences any pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeLibrary(_module: *mut core::ffi::c_void) -> i32 {
    1 // TRUE - success
}

/// FindFirstFileW - begin a directory search matching a pattern
///
/// Opens a search for files matching `file_name` (which may contain `*`/`?` wildcards)
/// and fills `find_data` with the first matching entry.  Returns a search handle on
/// success, or `INVALID_HANDLE_VALUE` on failure (sets last error).
///
/// # Safety
/// `file_name` must be a valid null-terminated UTF-16 string.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstFileW(
    file_name: *const u16,
    find_data: *mut u8,
) -> *mut core::ffi::c_void {
    const INVALID_HANDLE: *mut core::ffi::c_void = -1_i64 as usize as *mut core::ffi::c_void;

    if file_name.is_null() || find_data.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return INVALID_HANDLE;
    }
    let linux_path = wide_path_to_linux(file_name);
    let (dir_path, pattern) = split_dir_and_pattern(&linux_path);

    let entries: Vec<std::fs::DirEntry> = match std::fs::read_dir(&dir_path) {
        Ok(rd) => rd.filter_map(std::result::Result::ok).collect(),
        Err(e) => {
            let code = match e.kind() {
                std::io::ErrorKind::NotFound => 3,         // ERROR_PATH_NOT_FOUND
                std::io::ErrorKind::PermissionDenied => 5, // ERROR_ACCESS_DENIED
                _ => 2,
            };
            kernel32_SetLastError(code);
            return INVALID_HANDLE;
        }
    };

    // Find the first matching entry
    let first_idx = entries
        .iter()
        .position(|e| find_matches_pattern(&e.file_name().to_string_lossy(), &pattern));
    let Some(first_idx) = first_idx else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        return INVALID_HANDLE;
    };

    // Fill find_data with the first match
    fill_find_data(&entries[first_idx], find_data);

    // Allocate handle and store state atomically, enforcing the search-handle
    // limit inside the mutex to prevent a TOCTOU race.
    let handle = alloc_find_handle();
    let inserted = with_find_handles(|map| {
        if map.len() >= MAX_OPEN_FIND_HANDLES {
            return false;
        }
        map.insert(
            handle,
            DirSearchState {
                entries,
                current_index: first_idx + 1,
                pattern,
            },
        );
        true
    });
    if !inserted {
        kernel32_SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return INVALID_HANDLE;
    }

    kernel32_SetLastError(0);
    handle as *mut core::ffi::c_void
}

/// FindFirstFileExW - extended directory search (delegates to `FindFirstFileW`)
///
/// The `info_level`, `search_op`, `search_filter`, and `additional_flags` parameters
/// are ignored; this behaves like `FindFirstFileW` with the same handle registry.
///
/// # Safety
/// `filename` must be a valid null-terminated UTF-16 string.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstFileExW(
    filename: *const u16,
    _info_level: u32,
    find_data: *mut u8,
    _search_op: u32,
    _search_filter: *mut core::ffi::c_void,
    _additional_flags: u32,
) -> *mut core::ffi::c_void {
    kernel32_FindFirstFileW(filename, find_data)
}

/// FindNextFileW - advance a directory search to the next matching entry
///
/// Fills `find_data` with the next matching entry for the search started by
/// `FindFirstFileW`.  Returns TRUE (1) on success or FALSE (0) when there are no
/// more matching entries (sets last error to `ERROR_NO_MORE_FILES` = 18).
/// Entries for which metadata retrieval fails (e.g. broken symlinks) are skipped
/// transparently rather than terminating enumeration.
///
/// # Safety
/// `find_file` must be a valid search handle returned by `FindFirstFileW`.
/// `find_data` must point to at least 592 bytes (size of `WIN32_FIND_DATAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindNextFileW(
    find_file: *mut core::ffi::c_void,
    find_data: *mut u8,
) -> i32 {
    let handle = find_file as usize;

    loop {
        // Find the next matching entry and extract its path while holding the lock.
        let found_path = with_find_handles(|map| {
            let state = map.get_mut(&handle)?;
            while state.current_index < state.entries.len() {
                let idx = state.current_index;
                state.current_index += 1;
                if find_matches_pattern(
                    &state.entries[idx].file_name().to_string_lossy(),
                    &state.pattern,
                ) {
                    return Some(state.entries[idx].path());
                }
            }
            None
        });

        let Some(path) = found_path else {
            kernel32_SetLastError(18); // ERROR_NO_MORE_FILES
            return 0;
        };

        if !find_data.is_null() {
            if let Ok(meta) = std::fs::metadata(&path) {
                fill_find_data_from_path(&path, &meta, find_data);
                kernel32_SetLastError(0);
                return 1; // TRUE
            }
            // Metadata retrieval failed (e.g., broken symlink, permission error).
            // Skip this entry and try the next one rather than misreporting no more files.
            continue;
        }
        // find_data is null – caller only wants to know if more entries exist.
        kernel32_SetLastError(0);
        return 1;
    }
}

/// Fill a raw `WIN32_FIND_DATAW` buffer from a filesystem path and its metadata.
///
/// # Safety
/// `find_data` must point to a writable buffer of at least 592 bytes.
unsafe fn fill_find_data_from_path(
    path: &std::path::Path,
    meta: &std::fs::Metadata,
    find_data: *mut u8,
) {
    let attrs: u32 = if meta.is_dir() { 0x10 } else { 0x80 };
    let file_size = meta.len();
    let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    let unix_ns = modified
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let wt = (unix_ns / 100) + 116_444_736_000_000_000u128;
    let tl = wt as u32;
    let th = (wt >> 32) as u32;
    let sl = file_size as u32;
    let sh = (file_size >> 32) as u32;

    let ptr = find_data;
    // SAFETY: caller guarantees ≥592 bytes
    core::ptr::write_unaligned(ptr.cast::<u32>(), attrs);
    core::ptr::write_unaligned(ptr.add(4).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(8).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(12).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(16).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(20).cast::<u32>(), tl);
    core::ptr::write_unaligned(ptr.add(24).cast::<u32>(), th);
    core::ptr::write_unaligned(ptr.add(28).cast::<u32>(), sh);
    core::ptr::write_unaligned(ptr.add(32).cast::<u32>(), sl);
    core::ptr::write_unaligned(ptr.add(36).cast::<u32>(), 0u32);
    core::ptr::write_unaligned(ptr.add(40).cast::<u32>(), 0u32);

    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let copy_len = utf16.len().min(259);
    let fp = ptr.add(44).cast::<u16>();
    for (i, &ch) in utf16[..copy_len].iter().enumerate() {
        core::ptr::write_unaligned(fp.add(i), ch);
    }
    core::ptr::write_unaligned(fp.add(copy_len), 0u16);
    for i in (copy_len + 1)..260 {
        core::ptr::write_unaligned(fp.add(i), 0u16);
    }
    let ap = ptr.add(564).cast::<u16>();
    for i in 0..14 {
        core::ptr::write_unaligned(ap.add(i), 0u16);
    }
}

/// FindClose - closes a file search handle
///
/// Removes the search state associated with `find_file` from the handle registry.
/// Always returns TRUE (1); sets last error to `ERROR_INVALID_HANDLE` if the handle
/// was not found (but still returns TRUE for compatibility with Windows behavior).
///
/// # Safety
/// `find_file` must be a handle previously returned by `FindFirstFileW` / `FindFirstFileExW`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindClose(find_file: *mut core::ffi::c_void) -> i32 {
    let handle = find_file as usize;
    let removed = with_find_handles(|map| map.remove(&handle).is_some());
    if !removed {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
    }
    1 // TRUE - always succeeds (Windows FindClose always returns TRUE)
}

/// WaitOnAddress - waits for the value at the specified address to change
///
/// This is a stub implementation that does not perform any blocking wait and
/// simply returns immediately with TRUE (1).  It can be extended in the future
/// to provide real synchronization semantics if needed.
///
/// # Safety
/// All pointer arguments are accepted as opaque values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WaitOnAddress(
    _address: *mut core::ffi::c_void,
    _compare_address: *mut core::ffi::c_void,
    _address_size: usize,
    _milliseconds: u32,
) -> i32 {
    1 // TRUE - success
}

/// WakeByAddressAll - wakes all threads waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressAll(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// WakeByAddressSingle - wakes one thread waiting on an address
///
/// # Safety
/// This function is a no-op stub.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WakeByAddressSingle(_address: *mut core::ffi::c_void) {
    // No-op stub
}

/// GetACP - returns the current ANSI code page identifier
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetACP() -> u32 {
    // Return UTF-8 code page (65001) for compatibility
    65001
}

/// IsProcessorFeaturePresent - checks if a processor feature is present
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsProcessorFeaturePresent(feature: u32) -> i32 {
    // PF_FASTFAIL_AVAILABLE = 23
    // PF_SSE2_INSTRUCTIONS_AVAILABLE = 10
    // PF_NX_ENABLED = 12
    match feature {
        // SSE2 (10), NX (12), and FastFail (23) are available on x86-64
        10 | 12 | 23 => 1,
        _ => 0,
    }
}

/// IsDebuggerPresent - checks if a debugger is attached to the process
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsDebuggerPresent() -> i32 {
    0 // No debugger attached
}

/// GetStringTypeW - retrieves character type information for wide characters
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetStringTypeW(
    _dw_info_type: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_char_type: *mut u16,
) -> i32 {
    if lp_src_str.is_null() || lp_char_type.is_null() {
        return 0; // FALSE
    }

    let len = if cch_src == -1 {
        // Count until null terminator
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n
    } else {
        cch_src as usize
    };

    // Fill with basic character type info
    // C1_ALPHA = 0x100, C1_LOWER = 0x002, C1_UPPER = 0x001
    for i in 0..len {
        let ch = *lp_src_str.add(i);
        let mut char_type: u16 = 0;
        // Only classify ASCII-range characters
        if ch < 128 {
            let byte = ch as u8;
            if byte.is_ascii_alphabetic() {
                char_type |= 0x100; // C1_ALPHA
                if byte.is_ascii_lowercase() {
                    char_type |= 0x002; // C1_LOWER
                } else if byte.is_ascii_uppercase() {
                    char_type |= 0x001; // C1_UPPER
                }
            } else if byte.is_ascii_digit() {
                char_type |= 0x004; // C1_DIGIT
            } else if byte.is_ascii_whitespace() {
                char_type |= 0x008; // C1_SPACE
            } else if byte.is_ascii_punctuation() {
                char_type |= 0x010; // C1_PUNCT
            } else if byte.is_ascii_control() {
                char_type |= 0x020; // C1_CNTRL
            }
        }
        *lp_char_type.add(i) = char_type;
    }

    1 // TRUE (success)
}

/// HeapSize - returns the size of a memory block allocated from a heap
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_HeapSize(
    _heap: *mut core::ffi::c_void,
    _flags: u32,
    mem: *const core::ffi::c_void,
) -> usize {
    if mem.is_null() {
        return usize::MAX; // Error indicator
    }
    // We can't reliably determine the size of a Rust-allocated block
    // without tracking allocations. Return error to signal this limitation.
    usize::MAX
}

/// InitializeCriticalSectionAndSpinCount - initialize with spin count
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionAndSpinCount(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// InitializeCriticalSectionEx - extended initialization
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InitializeCriticalSectionEx(
    critical_section: *mut CriticalSection,
    _spin_count: u32,
    _flags: u32,
) -> i32 {
    kernel32_InitializeCriticalSection(critical_section);
    1 // TRUE (success)
}

/// FlsAlloc - allocate a fiber-local storage (FLS) index
///
/// FLS is similar to TLS but works with fibers. We implement it as a wrapper
/// around our TLS implementation since we don't support fibers.
///
/// # Safety
/// This function is unsafe as it deals with function pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsAlloc(_callback: *mut core::ffi::c_void) -> u32 {
    // Use TLS allocation since we don't support fibers
    kernel32_TlsAlloc()
}

/// FlsFree - free a fiber-local storage (FLS) index
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsFree(fls_index: u32) -> i32 {
    // Use TLS free since FLS maps to TLS
    kernel32_TlsFree(fls_index) as i32
}

/// FlsGetValue - get value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsGetValue(fls_index: u32) -> usize {
    kernel32_TlsGetValue(fls_index)
}

/// FlsSetValue - set value in fiber-local storage
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlsSetValue(fls_index: u32, fls_data: usize) -> i32 {
    kernel32_TlsSetValue(fls_index, fls_data) as i32
}

/// IsValidCodePage - check if a code page is valid
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsValidCodePage(code_page: u32) -> i32 {
    // Support common code pages
    match code_page {
        437 | 850 | 1252 | 65001 | 20127 => 1, // TRUE
        _ => 0,                                // FALSE
    }
}

/// GetOEMCP - get OEM code page
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetOEMCP() -> u32 {
    437 // US English OEM code page
}

/// GetCPInfo - get code page information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetCPInfo(code_page: u32, cp_info: *mut u8) -> i32 {
    if cp_info.is_null() {
        return 0; // FALSE
    }

    // CPINFO structure: MaxCharSize (UINT, 4 bytes) + DefaultChar (2 bytes) + LeadByte (12 bytes) = 18 bytes
    // Zero-initialize first
    core::ptr::write_bytes(cp_info, 0, 18);

    // Set MaxCharSize based on code page
    let max_char_size: u32 = match code_page {
        65001 => 4, // UTF-8: up to 4 bytes per character
        _ => 1,     // Single-byte code pages and default
    };
    core::ptr::copy_nonoverlapping((&raw const max_char_size).cast::<u8>(), cp_info, 4);

    // DefaultChar: '?' (0x3F)
    *cp_info.add(4) = 0x3F;

    1 // TRUE (success)
}

/// GetLocaleInfoW - get locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub unsafe extern "C" fn kernel32_GetLocaleInfoW(
    _locale: u32,
    _lc_type: u32,
    lp_lc_data: *mut u16,
    cch_data: i32,
) -> i32 {
    // When cch_data is 0, this is a size query: return required size
    if cch_data == 0 {
        // Return required size including null terminator
        return 2; // Minimum: one char + null
    }

    // Non-zero size with a null buffer is invalid
    if lp_lc_data.is_null() {
        return 0;
    }

    // Return a minimal response (just a null-terminated empty-ish string)
    if cch_data >= 1 {
        *lp_lc_data = 0; // Null terminator
    }
    1
}

/// LCMapStringW - map a string using locale information
///
/// # Safety
/// This function is unsafe as it deals with raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LCMapStringW(
    _locale: u32,
    _map_flags: u32,
    lp_src_str: *const u16,
    cch_src: i32,
    lp_dest_str: *mut u16,
    cch_dest: i32,
) -> i32 {
    if lp_src_str.is_null() {
        return 0;
    }

    let src_len = if cch_src == -1 {
        let mut n = 0;
        while *lp_src_str.add(n) != 0 {
            n += 1;
        }
        n + 1 // Include null terminator
    } else {
        cch_src as usize
    };

    if cch_dest == 0 {
        // Return required buffer size
        return src_len as i32;
    }

    if lp_dest_str.is_null() {
        // Invalid destination pointer when a non-zero length is requested
        return 0;
    }

    // Simple copy (no actual locale transformation)
    let copy_len = core::cmp::min(src_len, cch_dest as usize);
    core::ptr::copy_nonoverlapping(lp_src_str, lp_dest_str, copy_len);

    copy_len as i32
}

/// Tracks VirtualAlloc allocations so VirtualFree(MEM_RELEASE) can release the
/// correct size when the caller passes `dwSize = 0` (as the Windows API requires).
static VIRTUAL_ALLOC_TRACKER: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<usize, usize>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// VirtualAlloc - reserves, commits, or changes the state of a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory allocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualAlloc(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    _allocation_type: u32,
    _protect: u32,
) -> *mut core::ffi::c_void {
    if dw_size == 0 {
        return core::ptr::null_mut();
    }

    // Use mmap to allocate memory
    let addr = if lp_address.is_null() {
        core::ptr::null_mut()
    } else {
        lp_address
    };

    let ptr = libc::mmap(
        addr,
        dw_size,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );

    if ptr == libc::MAP_FAILED {
        core::ptr::null_mut()
    } else {
        // Record allocation size so VirtualFree can release the full region
        if let Ok(mut tracker) = VIRTUAL_ALLOC_TRACKER.lock() {
            tracker.insert(ptr as usize, dw_size);
        }
        ptr
    }
}

/// VirtualFree - releases, decommits, or releases and decommits a region of pages
///
/// # Safety
/// This function is unsafe as it deals with raw memory deallocation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualFree(
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    if lp_address.is_null() {
        return 0; // FALSE
    }

    // MEM_RELEASE = 0x8000
    if dw_free_type == 0x8000 {
        // Per the Windows API contract, dwSize must be 0 for MEM_RELEASE;
        // the OS releases the entire region originally reserved by VirtualAlloc.
        // We look up the original allocation size from our tracker.
        let size = if dw_size == 0 {
            VIRTUAL_ALLOC_TRACKER
                .lock()
                .ok()
                .and_then(|mut t| t.remove(&(lp_address as usize)))
                .unwrap_or(4096) // Fallback to one page if not tracked
        } else {
            // Non-standard usage; honour the caller-supplied size
            if let Ok(mut tracker) = VIRTUAL_ALLOC_TRACKER.lock() {
                tracker.remove(&(lp_address as usize));
            }
            dw_size
        };
        if libc::munmap(lp_address, size) == 0 {
            return 1; // TRUE
        }
    }

    0 // FALSE
}

/// DecodePointer - decodes a previously encoded pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_DecodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, pointers are not actually encoded, so just return as-is
    ptr
}

/// EncodePointer - encodes a pointer
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_EncodePointer(
    ptr: *mut core::ffi::c_void,
) -> *mut core::ffi::c_void {
    // In our emulation, we don't actually encode pointers
    ptr
}

/// GetTickCount64 - retrieves the number of milliseconds since system start
///
/// # Safety
/// This function is safe to call but marked unsafe for C ABI compatibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTickCount64() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts);
    (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
}

/// SetEvent - sets the specified event object to the signaled state
///
/// Signals the event and wakes waiters.  For manual-reset events, all waiters
/// are notified (`notify_all`); for auto-reset events only one waiter is
/// released (`notify_one`) to match Win32 semantics.  Returns TRUE (1) on
/// success, or FALSE (0) with `GetLastError() == ERROR_INVALID_HANDLE` if
/// `event` is not a handle created by `CreateEventW`.
///
/// # Panics
/// Panics if the internal event-state mutex is poisoned (another thread
/// panicked while holding the lock).
///
/// # Safety
/// `event` must be a handle returned by `CreateEventW`, or NULL/invalid (in
/// which case FALSE is returned).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEvent(event: *mut core::ffi::c_void) -> i32 {
    let handle = event as usize;
    let state_and_flag = with_event_handles(|map| {
        map.get(&handle)
            .map(|e| (Arc::clone(&e.state), e.manual_reset))
    });
    let Some((state, manual_reset)) = state_and_flag else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let (lock, cvar) = &*state;
    *lock.lock().unwrap() = true;
    if manual_reset {
        cvar.notify_all();
    } else {
        cvar.notify_one();
    }
    1 // TRUE
}

/// ResetEvent - resets the specified event object to the nonsignaled state
///
/// Clears the event so that threads waiting on it will block.  Returns TRUE
/// (1) on success, or FALSE (0) with `GetLastError() == ERROR_INVALID_HANDLE`
/// if `event` is not a handle created by `CreateEventW`.
///
/// # Panics
/// Panics if the internal event-state mutex is poisoned (another thread
/// panicked while holding the lock).
///
/// # Safety
/// `event` must be a handle returned by `CreateEventW`, or NULL/invalid (in
/// which case FALSE is returned).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ResetEvent(event: *mut core::ffi::c_void) -> i32 {
    let handle = event as usize;
    let state_arc = with_event_handles(|map| map.get(&handle).map(|e| Arc::clone(&e.state)));
    let Some(state) = state_arc else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    let (lock, _cvar) = &*state;
    *lock.lock().unwrap() = false;
    1 // TRUE
}

/// `IsDBCSLeadByteEx` – test whether a byte is a DBCS lead byte in the given code page.
///
/// We only support single-byte encodings (code pages 0 and 65001/UTF-8), so
/// this always returns FALSE (0).
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsDBCSLeadByteEx(_code_page: u32, _test_char: u8) -> i32 {
    0 // FALSE – not a DBCS lead byte
}

// ── Time APIs ────────────────────────────────────────────────────────────

/// Windows SYSTEMTIME structure (16 bytes, 8 × u16 fields).
#[repr(C)]
pub struct SystemTime {
    pub w_year: u16,
    pub w_month: u16,
    pub w_day_of_week: u16,
    pub w_day: u16,
    pub w_hour: u16,
    pub w_minute: u16,
    pub w_second: u16,
    pub w_milliseconds: u16,
}

/// `GetSystemTime` — fill a SYSTEMTIME pointer with the current UTC time.
///
/// # Safety
/// Caller must ensure `system_time` points to at least 16 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemTime(system_time: *mut SystemTime) {
    if system_time.is_null() {
        return;
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: &mut ts is a valid pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut ts) };
    let mut tm_buf: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: ts.tv_sec is a valid time_t; tm_buf is a valid out-pointer.
    unsafe { libc::gmtime_r(&raw const ts.tv_sec, &raw mut tm_buf) };
    // SAFETY: system_time is checked non-null above.
    unsafe {
        (*system_time).w_year = (tm_buf.tm_year + 1900) as u16;
        (*system_time).w_month = (tm_buf.tm_mon + 1) as u16;
        (*system_time).w_day_of_week = tm_buf.tm_wday as u16;
        (*system_time).w_day = tm_buf.tm_mday as u16;
        (*system_time).w_hour = tm_buf.tm_hour as u16;
        (*system_time).w_minute = tm_buf.tm_min as u16;
        (*system_time).w_second = tm_buf.tm_sec as u16;
        (*system_time).w_milliseconds = (ts.tv_nsec / 1_000_000) as u16;
    }
}

/// `GetLocalTime` — fill a SYSTEMTIME pointer with the current local time.
///
/// # Safety
/// Caller must ensure `system_time` points to at least 16 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLocalTime(system_time: *mut SystemTime) {
    if system_time.is_null() {
        return;
    }
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: &mut ts is a valid pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut ts) };
    let mut tm_buf: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: ts.tv_sec is a valid time_t; tm_buf is a valid out-pointer.
    unsafe { libc::localtime_r(&raw const ts.tv_sec, &raw mut tm_buf) };
    // SAFETY: system_time is checked non-null above.
    unsafe {
        (*system_time).w_year = (tm_buf.tm_year + 1900) as u16;
        (*system_time).w_month = (tm_buf.tm_mon + 1) as u16;
        (*system_time).w_day_of_week = tm_buf.tm_wday as u16;
        (*system_time).w_day = tm_buf.tm_mday as u16;
        (*system_time).w_hour = tm_buf.tm_hour as u16;
        (*system_time).w_minute = tm_buf.tm_min as u16;
        (*system_time).w_second = tm_buf.tm_sec as u16;
        (*system_time).w_milliseconds = (ts.tv_nsec / 1_000_000) as u16;
    }
}

/// `SystemTimeToFileTime` — convert a SYSTEMTIME to a FILETIME (100-ns intervals since 1601-01-01).
///
/// Returns 1 (TRUE) on success, 0 if either pointer is null or the SYSTEMTIME fields are invalid.
///
/// # Safety
/// `system_time` must point to a valid `SystemTime` (16 bytes).
/// `file_time` must point to a valid `FileTime` (8 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SystemTimeToFileTime(
    system_time: *const u8,
    file_time: *mut FileTime,
) -> i32 {
    if system_time.is_null() || file_time.is_null() {
        return 0;
    }
    // SAFETY: Caller guarantees system_time points to a valid SystemTime.
    let st = unsafe { &*(system_time.cast::<SystemTime>()) };

    // Validate SYSTEMTIME fields per Win32 contract (returns FALSE for invalid dates).
    if st.w_month < 1
        || st.w_month > 12
        || st.w_day < 1
        || st.w_day > 31
        || st.w_hour > 23
        || st.w_minute > 59
        || st.w_second > 59
        || st.w_milliseconds > 999
        || st.w_year < 1601
    {
        return 0; // FALSE – invalid input
    }

    let mut tm_val: libc::tm = unsafe { core::mem::zeroed() };
    tm_val.tm_year = i32::from(st.w_year) - 1900;
    tm_val.tm_mon = i32::from(st.w_month) - 1;
    tm_val.tm_mday = i32::from(st.w_day);
    tm_val.tm_hour = i32::from(st.w_hour);
    tm_val.tm_min = i32::from(st.w_minute);
    tm_val.tm_sec = i32::from(st.w_second);
    tm_val.tm_isdst = -1;
    // SAFETY: tm_val fields are set above.
    let unix_time = unsafe { libc::timegm(&raw mut tm_val) };

    // Guard against dates before the Windows FILETIME epoch (1601-01-01).
    let adjusted = unix_time + EPOCH_DIFF;
    if adjusted < 0 {
        return 0; // FALSE – date before FILETIME epoch (should not happen after year validation)
    }
    let intervals = adjusted as u64 * 10_000_000 + u64::from(st.w_milliseconds) * 10_000;
    // SAFETY: file_time is checked non-null above.
    unsafe {
        (*file_time).low_date_time = intervals as u32;
        (*file_time).high_date_time = (intervals >> 32) as u32;
    }
    1 // TRUE
}

/// `FileTimeToSystemTime` — convert a FILETIME to a SYSTEMTIME.
///
/// Returns 1 (TRUE) on success, 0 if either pointer is null.
///
/// # Safety
/// `file_time` must point to a valid `FileTime` (8 bytes).
/// `system_time` must point to at least 16 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FileTimeToSystemTime(
    file_time: *const FileTime,
    system_time: *mut SystemTime,
) -> i32 {
    if file_time.is_null() || system_time.is_null() {
        return 0;
    }
    // SAFETY: Caller guarantees file_time points to a valid FileTime.
    let ft = unsafe { &*file_time };
    let intervals = u64::from(ft.low_date_time) | (u64::from(ft.high_date_time) << 32);
    let unix_time = (intervals / 10_000_000) as i64 - EPOCH_DIFF;
    let millis = ((intervals % 10_000_000) / 10_000) as u16;
    let mut tm_buf: libc::tm = unsafe { core::mem::zeroed() };
    let time_t_val: libc::time_t = unix_time;
    // SAFETY: time_t_val is a valid Unix timestamp; tm_buf is a valid out-pointer.
    unsafe { libc::gmtime_r(&raw const time_t_val, &raw mut tm_buf) };
    // SAFETY: system_time is checked non-null above.
    unsafe {
        (*system_time).w_year = (tm_buf.tm_year + 1900) as u16;
        (*system_time).w_month = (tm_buf.tm_mon + 1) as u16;
        (*system_time).w_day_of_week = tm_buf.tm_wday as u16;
        (*system_time).w_day = tm_buf.tm_mday as u16;
        (*system_time).w_hour = tm_buf.tm_hour as u16;
        (*system_time).w_minute = tm_buf.tm_min as u16;
        (*system_time).w_second = tm_buf.tm_sec as u16;
        (*system_time).w_milliseconds = millis;
    }
    1 // TRUE
}

/// `GetTickCount` — return the number of milliseconds since system start as a 32-bit value.
///
/// This is a 32-bit wrapper around `GetTickCount64`; the value wraps around after ~49.7 days.
///
/// # Safety
/// This function is safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTickCount() -> u32 {
    // SAFETY: kernel32_GetTickCount64 is always safe to call.
    (unsafe { kernel32_GetTickCount64() }) as u32
}

// ── Local memory management ──────────────────────────────────────────────

/// `LocalAlloc` — allocate local memory.
///
/// Delegates to `HeapAlloc`.  `LMEM_ZEROINIT` (0x0040) maps to `HEAP_ZERO_MEMORY` (0x0008).
///
/// # Safety
/// The caller must eventually free the returned pointer with `LocalFree`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LocalAlloc(flags: u32, bytes: usize) -> *mut core::ffi::c_void {
    let heap_flags = if flags & 0x0040 != 0 {
        HEAP_ZERO_MEMORY
    } else {
        0
    };
    // SAFETY: Delegating to HeapAlloc with validated flags.
    unsafe { kernel32_HeapAlloc(core::ptr::null_mut(), heap_flags, bytes) }
}

/// `LocalFree` — free local memory previously allocated by `LocalAlloc`.
///
/// Delegates to `HeapFree`.  Returns NULL on success; returns the original handle on failure
/// (per Win32 contract).
///
/// # Safety
/// `mem` must have been allocated by `LocalAlloc` (or `HeapAlloc`), or be NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_LocalFree(mem: *mut core::ffi::c_void) -> *mut core::ffi::c_void {
    // SAFETY: Delegating to HeapFree; caller guarantees mem is a valid allocation.
    let ok = unsafe { kernel32_HeapFree(core::ptr::null_mut(), 0, mem) };
    if ok != 0 {
        core::ptr::null_mut() // success
    } else {
        mem // failure: return the original handle per Win32 contract
    }
}

// ── Interlocked atomic operations ────────────────────────────────────────

/// `InterlockedIncrement` — atomically increment `*addend` by 1; return new value.
///
/// # Safety
/// `addend` must be a valid, aligned pointer to an `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedIncrement(addend: *mut i32) -> i32 {
    // SAFETY: Caller guarantees addend is a valid aligned i32 pointer.
    let atomic = unsafe { &*(addend.cast::<AtomicI32>()) };
    atomic.fetch_add(1, Ordering::SeqCst) + 1
}

/// `InterlockedDecrement` — atomically decrement `*addend` by 1; return new value.
///
/// # Safety
/// `addend` must be a valid, aligned pointer to an `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedDecrement(addend: *mut i32) -> i32 {
    // SAFETY: Caller guarantees addend is a valid aligned i32 pointer.
    let atomic = unsafe { &*(addend.cast::<AtomicI32>()) };
    atomic.fetch_sub(1, Ordering::SeqCst) - 1
}

/// `InterlockedExchange` — atomically set `*target = value`; return the old value.
///
/// # Safety
/// `target` must be a valid, aligned pointer to an `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedExchange(target: *mut i32, value: i32) -> i32 {
    // SAFETY: Caller guarantees target is a valid aligned i32 pointer.
    let atomic = unsafe { &*(target.cast::<AtomicI32>()) };
    atomic.swap(value, Ordering::SeqCst)
}

/// `InterlockedExchangeAdd` — atomically add `value` to `*addend`; return the old value.
///
/// # Safety
/// `addend` must be a valid, aligned pointer to an `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedExchangeAdd(addend: *mut i32, value: i32) -> i32 {
    // SAFETY: Caller guarantees addend is a valid aligned i32 pointer.
    let atomic = unsafe { &*(addend.cast::<AtomicI32>()) };
    atomic.fetch_add(value, Ordering::SeqCst)
}

/// `InterlockedCompareExchange` — CAS: if `*dest == comparand`, set `*dest = exchange`; return old `*dest`.
///
/// # Safety
/// `dest` must be a valid, aligned pointer to an `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedCompareExchange(
    dest: *mut i32,
    exchange: i32,
    comparand: i32,
) -> i32 {
    // SAFETY: Caller guarantees dest is a valid aligned i32 pointer.
    let atomic = unsafe { &*(dest.cast::<AtomicI32>()) };
    atomic
        .compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|e| e)
}

/// `InterlockedCompareExchange64` — CAS on 64-bit value; return old `*dest`.
///
/// # Safety
/// `dest` must be a valid, 8-byte-aligned pointer to an `i64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_InterlockedCompareExchange64(
    dest: *mut i64,
    exchange: i64,
    comparand: i64,
) -> i64 {
    // SAFETY: Caller guarantees dest is a valid aligned i64 pointer.
    let atomic = unsafe { &*(dest.cast::<AtomicI64>()) };
    atomic
        .compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst)
        .unwrap_or_else(|e| e)
}

// ── System info helpers ──────────────────────────────────────────────────

/// `IsWow64Process` — determine whether the process is running under WOW64.
///
/// Always returns TRUE (1) with `*is_wow64` set to FALSE (0) because we are
/// running as a native 64-bit process.
///
/// # Safety
/// `is_wow64` must be a valid pointer to an `i32` or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsWow64Process(
    _process: *mut core::ffi::c_void,
    is_wow64: *mut i32,
) -> i32 {
    if !is_wow64.is_null() {
        // SAFETY: is_wow64 is checked non-null above.
        unsafe { *is_wow64 = 0 };
    }
    1 // TRUE – call succeeded; WOW64 = FALSE
}

/// `GetNativeSystemInfo` — retrieve information about the native system.
///
/// Delegates to `GetSystemInfo` since we run natively on x86-64.
///
/// # Safety
/// `system_info` must point to a writable buffer large enough for a SYSTEM_INFO structure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetNativeSystemInfo(system_info: *mut u8) {
    // SAFETY: Delegating with the same pointer contract.
    unsafe { kernel32_GetSystemInfo(system_info) }
}

// ── Phase 26: Mutex / Semaphore ───────────────────────────────────────────

/// # Safety
/// ptr must be a valid null-terminated UTF-16 string
unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
    let mut chars = Vec::new();
    let mut i = 0;
    while *ptr.add(i) != 0 {
        chars.push(*ptr.add(i));
        i += 1;
    }
    String::from_utf16_lossy(&chars)
}

/// CreateMutexW - Creates or opens a named or unnamed mutex object
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string or NULL.
///
/// # Panics
/// Panics if an internal mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateMutexW(
    _attrs: *mut u8,
    initial_owner: i32,
    name: *const u16,
) -> *mut core::ffi::c_void {
    let name_opt = if name.is_null() {
        None
    } else {
        // SAFETY: caller guarantees valid null-terminated UTF-16 string
        Some(wide_ptr_to_string(name))
    };

    // Build the new entry upfront so it can be inserted if no existing named
    // mutex is found. The state is constructed before acquiring the lock, but
    // the entry is only inserted when we confirm no duplicate name exists.
    let state: MutexStateArc = Arc::new((Mutex::new(None), Condvar::new()));
    if initial_owner != 0 {
        // SAFETY: SYS_gettid is always safe
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        *state.0.lock().unwrap() = Some((tid, 1));
    }

    // Perform the lookup-and-insert atomically under a single SYNC_HANDLES lock.
    let handle = with_sync_handles(|map| {
        // Return the existing handle if a mutex with this name already exists.
        if let Some(ref n) = name_opt {
            for (&h, entry) in map.iter() {
                if let SyncObjectEntry::Mutex { name: Some(en), .. } = entry
                    && en == n
                {
                    return h;
                }
            }
        }
        // No existing named mutex found: allocate a new handle and insert.
        let h = alloc_sync_handle();
        map.insert(
            h,
            SyncObjectEntry::Mutex {
                name: name_opt.clone(),
                state: Arc::clone(&state),
            },
        );
        h
    });
    handle as *mut core::ffi::c_void
}

/// CreateMutexA - Creates or opens a named or unnamed mutex object (ANSI)
///
/// # Safety
/// `name` must be a valid null-terminated ANSI string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateMutexA(
    attrs: *mut u8,
    initial_owner: i32,
    name: *const u8,
) -> *mut core::ffi::c_void {
    let wide_name: Vec<u16>;
    let name_w = if name.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: caller guarantees valid null-terminated ANSI string
        let s = unsafe { std::ffi::CStr::from_ptr(name.cast::<i8>()) }
            .to_string_lossy()
            .into_owned();
        wide_name = s.encode_utf16().chain(std::iter::once(0)).collect();
        wide_name.as_ptr()
    };
    kernel32_CreateMutexW(attrs, initial_owner, name_w)
}

/// OpenMutexW - Opens an existing named mutex object
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OpenMutexW(
    _desired_access: u32,
    _inherit_handle: i32,
    name: *const u16,
) -> *mut core::ffi::c_void {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 string
    let name_str = wide_ptr_to_string(name);
    let existing = with_sync_handles(|map| {
        for (&h, entry) in map.iter() {
            if let SyncObjectEntry::Mutex { name: Some(en), .. } = entry
                && *en == name_str
            {
                return Some(h);
            }
        }
        None
    });
    if let Some(h) = existing {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// ReleaseMutex - Releases ownership of the specified mutex object
///
/// # Safety
/// `mutex` must be a valid mutex handle returned by CreateMutexW/A.
///
/// # Panics
/// Panics if an internal mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReleaseMutex(mutex: *mut core::ffi::c_void) -> i32 {
    let handle_val = mutex as usize;
    // SAFETY: SYS_gettid is always safe
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let released = with_sync_handles(|map| {
        if let Some(SyncObjectEntry::Mutex { state, .. }) = map.get(&handle_val) {
            let (lock, cvar) = &**state;
            let mut guard = lock.lock().unwrap();
            if let Some((owner, count)) = *guard
                && owner == tid
            {
                if count > 1 {
                    *guard = Some((owner, count - 1));
                } else {
                    *guard = None;
                    cvar.notify_one();
                }
                return true;
            }
        }
        false
    });
    if !released {
        // SAFETY: no pointers are dereferenced.
        unsafe { kernel32_SetLastError(288) }; // ERROR_NOT_OWNER
    }
    i32::from(released)
}

/// CreateSemaphoreW - Creates or opens a named or unnamed semaphore object
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateSemaphoreW(
    _attrs: *mut u8,
    initial_count: i32,
    max_count: i32,
    name: *const u16,
) -> *mut core::ffi::c_void {
    if initial_count < 0 || max_count <= 0 || initial_count > max_count {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }
    let name_opt = if name.is_null() {
        None
    } else {
        // SAFETY: caller guarantees valid null-terminated UTF-16 string
        Some(wide_ptr_to_string(name))
    };

    // Build the state before acquiring the lock; insert only when no named
    // duplicate is found (atomic lookup-and-insert under SYNC_HANDLES).
    let state: Arc<(Mutex<i32>, Condvar)> = Arc::new((Mutex::new(initial_count), Condvar::new()));

    let handle = with_sync_handles(|map| {
        // Return existing handle if a semaphore with this name already exists.
        if let Some(ref n) = name_opt {
            for (&h, entry) in map.iter() {
                if let SyncObjectEntry::Semaphore { name: Some(en), .. } = entry
                    && en == n
                {
                    return h;
                }
            }
        }
        // No existing named semaphore: allocate and insert.
        let h = alloc_sync_handle();
        map.insert(
            h,
            SyncObjectEntry::Semaphore {
                name: name_opt.clone(),
                max_count,
                state: Arc::clone(&state),
            },
        );
        h
    });
    handle as *mut core::ffi::c_void
}

/// CreateSemaphoreA - Creates or opens a named or unnamed semaphore object (ANSI)
///
/// # Safety
/// `name` must be a valid null-terminated ANSI string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateSemaphoreA(
    attrs: *mut u8,
    initial_count: i32,
    max_count: i32,
    name: *const u8,
) -> *mut core::ffi::c_void {
    let wide_name: Vec<u16>;
    let name_w = if name.is_null() {
        core::ptr::null()
    } else {
        // SAFETY: caller guarantees valid null-terminated ANSI string
        let s = unsafe { std::ffi::CStr::from_ptr(name.cast::<i8>()) }
            .to_string_lossy()
            .into_owned();
        wide_name = s.encode_utf16().chain(std::iter::once(0)).collect();
        wide_name.as_ptr()
    };
    kernel32_CreateSemaphoreW(attrs, initial_count, max_count, name_w)
}

/// OpenSemaphoreW - Opens an existing named semaphore object
///
/// # Safety
/// `name` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OpenSemaphoreW(
    _desired_access: u32,
    _inherit_handle: i32,
    name: *const u16,
) -> *mut core::ffi::c_void {
    if name.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 string
    let name_str = wide_ptr_to_string(name);
    let existing = with_sync_handles(|map| {
        for (&h, entry) in map.iter() {
            if let SyncObjectEntry::Semaphore { name: Some(en), .. } = entry
                && *en == name_str
            {
                return Some(h);
            }
        }
        None
    });
    if let Some(h) = existing {
        h as *mut core::ffi::c_void
    } else {
        kernel32_SetLastError(2); // ERROR_FILE_NOT_FOUND
        core::ptr::null_mut()
    }
}

/// ReleaseSemaphore - Increases the count of the specified semaphore object
///
/// # Safety
/// `semaphore` must be a valid semaphore handle.
///
/// # Panics
/// Panics if an internal mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReleaseSemaphore(
    semaphore: *mut core::ffi::c_void,
    release_count: i32,
    previous_count: *mut i32,
) -> i32 {
    if release_count <= 0 {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let handle_val = semaphore as usize;
    // Err(true) = handle not found; Err(false) = would exceed max_count
    let result = with_sync_handles(|map| {
        if let Some(SyncObjectEntry::Semaphore {
            state, max_count, ..
        }) = map.get(&handle_val)
        {
            let (lock, cvar) = &**state;
            let mut count = lock.lock().unwrap();
            let prev = *count;
            let new_count = prev.saturating_add(release_count);
            if new_count > *max_count {
                return Err(false); // ERROR_TOO_MANY_POSTS
            }
            *count = new_count;
            for _ in 0..release_count {
                cvar.notify_one();
            }
            Ok(prev)
        } else {
            Err(true) // ERROR_INVALID_HANDLE
        }
    });
    match result {
        Ok(prev) => {
            if !previous_count.is_null() {
                // SAFETY: caller guarantees valid pointer
                unsafe { *previous_count = prev };
            }
            1
        }
        Err(true) => {
            kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
            0
        }
        Err(false) => {
            kernel32_SetLastError(298); // ERROR_TOO_MANY_POSTS
            0
        }
    }
}

// ── Phase 26: Console Extensions ──────────────────────────────────────────

/// SetConsoleMode - Sets the input mode of a console's input buffer or output mode
///
/// # Safety
/// `console` must be a valid console handle or pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleMode(
    _console: *mut core::ffi::c_void,
    _mode: u32,
) -> i32 {
    1 // TRUE - succeed silently
}

/// SetConsoleTitleW - Sets the title bar string for the current console window
///
/// # Safety
/// `title` must be a valid null-terminated UTF-16 string.
///
/// # Panics
/// Panics if an internal mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleTitleW(title: *const u16) -> i32 {
    if title.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 string
    let title_str = wide_ptr_to_string(title);
    let mut guard = CONSOLE_TITLE.lock().unwrap();
    *guard = Some(title_str);
    1
}

/// SetConsoleTitleA - Sets the title bar string for the current console window (ANSI)
///
/// # Safety
/// `title` must be a valid null-terminated ANSI string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetConsoleTitleA(title: *const u8) -> i32 {
    if title.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees valid null-terminated ANSI string
    let s = std::ffi::CStr::from_ptr(title.cast::<i8>())
        .to_string_lossy()
        .into_owned();
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    kernel32_SetConsoleTitleW(wide.as_ptr())
}

/// GetConsoleTitleW - Retrieves the title bar string for the current console window
///
/// # Safety
/// `buffer` must point to a valid writable buffer of at least `size` u16 elements.
///
/// # Panics
/// Panics if an internal mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleTitleW(buffer: *mut u16, size: u32) -> u32 {
    let guard = CONSOLE_TITLE.lock().unwrap();
    let title = guard.as_deref().unwrap_or("");
    // SAFETY: caller guarantees valid buffer with `size` elements
    copy_utf8_to_wide(title, buffer, size)
}

/// AllocConsole - Allocates a new console for the calling process
///
/// # Safety
/// This function is always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_AllocConsole() -> i32 {
    1 // TRUE - already have a console (or headless)
}

/// FreeConsole - Detaches the calling process from its console
///
/// # Safety
/// This function is always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FreeConsole() -> i32 {
    1 // TRUE
}

/// GetConsoleWindow - Retrieves the window handle used by the console
///
/// # Safety
/// This function is always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetConsoleWindow() -> *mut core::ffi::c_void {
    core::ptr::null_mut() // headless: no window
}

// ── Phase 26: String Utilities ─────────────────────────────────────────────

/// lstrlenA - Calculates the length of the specified string (ANSI)
///
/// # Safety
/// `string` must be a valid null-terminated ANSI string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrlenA(string: *const u8) -> i32 {
    if string.is_null() {
        return 0;
    }
    // SAFETY: caller guarantees valid null-terminated string
    let mut len = 0usize;
    while unsafe { *string.add(len) } != 0 {
        len += 1;
    }
    len as i32
}

/// lstrcpyW - Copies a string to a buffer (wide)
///
/// # Safety
/// `dst` must point to a valid writable buffer large enough for `src`.
/// `src` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcpyW(dst: *mut u16, src: *const u16) -> *mut u16 {
    if dst.is_null() || src.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees valid pointers with sufficient space
    let mut i = 0usize;
    loop {
        let ch = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = ch };
        if ch == 0 {
            break;
        }
        i += 1;
    }
    dst
}

/// lstrcpyA - Copies a string to a buffer (ANSI)
///
/// # Safety
/// `dst` must point to a valid writable buffer large enough for `src`.
/// `src` must be a valid null-terminated ANSI string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcpyA(dst: *mut u8, src: *const u8) -> *mut u8 {
    if dst.is_null() || src.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: caller guarantees valid pointers with sufficient space
    let mut i = 0usize;
    loop {
        let ch = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = ch };
        if ch == 0 {
            break;
        }
        i += 1;
    }
    dst
}

/// lstrcmpW - Compares two wide strings (case-sensitive)
///
/// # Safety
/// Both strings must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcmpW(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 strings
    let str1 = wide_ptr_to_string(s1);
    let str2 = wide_ptr_to_string(s2);
    match str1.cmp(&str2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// lstrcmpA - Compares two ANSI strings (case-sensitive)
///
/// # Safety
/// Both strings must be valid null-terminated ANSI strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcmpA(s1: *const u8, s2: *const u8) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    // SAFETY: caller guarantees valid null-terminated ANSI strings
    let mut i = 0usize;
    loop {
        let c1 = unsafe { *s1.add(i) };
        let c2 = unsafe { *s2.add(i) };
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// lstrcmpiW - Compares two wide strings (case-insensitive)
///
/// # Safety
/// Both strings must be valid null-terminated UTF-16 strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcmpiW(s1: *const u16, s2: *const u16) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 strings
    let str1 = wide_ptr_to_string(s1).to_lowercase();
    let str2 = wide_ptr_to_string(s2).to_lowercase();
    match str1.cmp(&str2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// lstrcmpiA - Compares two ANSI strings (case-insensitive)
///
/// # Safety
/// Both strings must be valid null-terminated ANSI strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_lstrcmpiA(s1: *const u8, s2: *const u8) -> i32 {
    if s1.is_null() && s2.is_null() {
        return 0;
    }
    if s1.is_null() {
        return -1;
    }
    if s2.is_null() {
        return 1;
    }
    // SAFETY: caller guarantees valid null-terminated ANSI strings
    let mut i = 0usize;
    loop {
        let c1 = unsafe { *s1.add(i) }.to_ascii_lowercase();
        let c2 = unsafe { *s2.add(i) }.to_ascii_lowercase();
        if c1 != c2 {
            return i32::from(c1) - i32::from(c2);
        }
        if c1 == 0 {
            return 0;
        }
        i += 1;
    }
}

/// OutputDebugStringW - Sends a wide string to the debugger (writes to stderr)
///
/// # Safety
/// `output_string` must be a valid null-terminated UTF-16 string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OutputDebugStringW(output_string: *const u16) {
    if output_string.is_null() {
        return;
    }
    // SAFETY: caller guarantees valid null-terminated UTF-16 string
    let s = wide_ptr_to_string(output_string);
    eprintln!("[OutputDebugString] {s}");
}

/// OutputDebugStringA - Sends an ANSI string to the debugger (writes to stderr)
///
/// # Safety
/// `output_string` must be a valid null-terminated ANSI string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OutputDebugStringA(output_string: *const u8) {
    if output_string.is_null() {
        return;
    }
    // SAFETY: caller guarantees valid null-terminated ANSI string
    let s = std::ffi::CStr::from_ptr(output_string.cast::<i8>()).to_string_lossy();
    eprintln!("[OutputDebugString] {s}");
}

// ── Phase 26: Drive / Volume APIs ─────────────────────────────────────────

const DRIVE_FIXED: u32 = 3;

/// GetDriveTypeW - Determines whether a disk drive is a removable, fixed, CD-ROM, RAM disk, or network drive
///
/// # Safety
/// `root_path_name` must be a valid null-terminated UTF-16 string or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetDriveTypeW(_root_path_name: *const u16) -> u32 {
    DRIVE_FIXED
}

/// GetLogicalDrives - Retrieves a bitmask representing currently available disk drives
///
/// # Safety
/// This function is always safe to call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLogicalDrives() -> u32 {
    0x4 // Bit 2 set = C: drive only
}

/// GetLogicalDriveStringsW - Fills a buffer with strings for valid drives in the system
///
/// # Safety
/// `buffer` must point to a writable buffer of at least `buffer_length` u16 elements.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetLogicalDriveStringsW(
    buffer_length: u32,
    buffer: *mut u16,
) -> u32 {
    // "C:\\\0\0" in wide chars = ['C', ':', '\\', 0, 0] = 5 u16s
    let drive_str: &[u16] = &[
        u16::from(b'C'),
        u16::from(b':'),
        u16::from(b'\\'),
        0u16,
        0u16,
    ];
    let required = drive_str.len() as u32;
    if buffer.is_null() || buffer_length < required {
        return required;
    }
    // SAFETY: caller guarantees valid writable buffer of at least buffer_length u16s
    for (i, &ch) in drive_str.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    required - 1
}

/// GetDiskFreeSpaceExW - Retrieves information about the amount of space available on a disk volume
///
/// # Safety
/// Output pointers must be valid or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetDiskFreeSpaceExW(
    _dir: *const u16,
    free_bytes: *mut u64,
    total_bytes: *mut u64,
    total_free_bytes: *mut u64,
) -> i32 {
    const TOTAL: u64 = 20 * 1024 * 1024 * 1024;
    const FREE: u64 = 10 * 1024 * 1024 * 1024;
    if !free_bytes.is_null() {
        // SAFETY: caller guarantees valid pointer
        *free_bytes = FREE;
    }
    if !total_bytes.is_null() {
        // SAFETY: caller guarantees valid pointer
        *total_bytes = TOTAL;
    }
    if !total_free_bytes.is_null() {
        // SAFETY: caller guarantees valid pointer
        *total_free_bytes = FREE;
    }
    1 // TRUE
}

/// GetVolumeInformationW - Returns information about a file system and volume
///
/// # Safety
/// Output pointers must be valid buffers or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetVolumeInformationW(
    _root: *const u16,
    volume_name: *mut u16,
    volume_name_size: u32,
    serial: *mut u32,
    max_component: *mut u32,
    fs_flags: *mut u32,
    fs_name: *mut u16,
    fs_name_size: u32,
) -> i32 {
    if !volume_name.is_null() && volume_name_size > 0 {
        // SAFETY: caller guarantees valid writable buffer
        copy_utf8_to_wide("LITEBOX", volume_name, volume_name_size);
    }
    if !serial.is_null() {
        // SAFETY: caller guarantees valid pointer
        *serial = 0x1234_5678;
    }
    if !max_component.is_null() {
        // SAFETY: caller guarantees valid pointer
        *max_component = 255;
    }
    if !fs_flags.is_null() {
        // SAFETY: caller guarantees valid pointer
        *fs_flags = 0x0003;
    }
    if !fs_name.is_null() && fs_name_size > 0 {
        // SAFETY: caller guarantees valid writable buffer
        copy_utf8_to_wide("NTFS", fs_name, fs_name_size);
    }
    1 // TRUE
}

// ── Phase 26: Computer Name ───────────────────────────────────────────────

/// GetComputerNameW - Retrieves the NetBIOS name of the local computer
///
/// # Safety
/// `buffer` must point to a valid writable buffer; `size` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetComputerNameW(buffer: *mut u16, size: *mut u32) -> i32 {
    if size.is_null() {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }
    let hostname = get_hostname();
    let utf16: Vec<u16> = hostname.encode_utf16().collect();
    let needed = utf16.len() as u32 + 1;
    // SAFETY: size is checked above
    let buf_size = *size;
    *size = needed;
    if buffer.is_null() || buf_size < needed {
        kernel32_SetLastError(234); // ERROR_MORE_DATA
        return 0;
    }
    // SAFETY: caller guarantees valid buffer of buf_size u16s
    for (i, &ch) in utf16.iter().enumerate() {
        *buffer.add(i) = ch;
    }
    *buffer.add(utf16.len()) = 0;
    *size = utf16.len() as u32;
    1
}

/// GetComputerNameExW - Retrieves a NetBIOS or DNS name associated with the local computer
///
/// # Safety
/// `buffer` must point to a valid writable buffer; `size` must be a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetComputerNameExW(
    _name_type: u32,
    buffer: *mut u16,
    size: *mut u32,
) -> i32 {
    kernel32_GetComputerNameW(buffer, size)
}

fn get_hostname() -> String {
    if let Ok(s) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let trimmed = s.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    let mut buf = vec![0u8; 256];
    // SAFETY: buf is a valid mutable buffer of 256 bytes
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<i8>(), buf.len()) };
    if ret == 0
        && let Some(end) = buf.iter().position(|&b| b == 0)
        && let Ok(s) = std::str::from_utf8(&buf[..end])
    {
        return s.to_owned();
    }
    "localhost".to_owned()
}

// ── Phase 27: Thread Management ──────────────────────────────────────────────

/// SetThreadPriority - sets the priority value for the specified thread
/// In this emulation environment, all threads run at normal priority. This function
/// accepts the priority value and always returns TRUE (success).
/// # Safety
/// `thread` is accepted as an opaque handle; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetThreadPriority(
    _thread: *mut core::ffi::c_void,
    _priority: i32,
) -> i32 {
    1 // TRUE
}

/// GetThreadPriority - retrieves the priority value for the specified thread
/// Returns THREAD_PRIORITY_NORMAL (0) for all threads.
/// # Safety
/// `thread` is accepted as an opaque handle; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetThreadPriority(_thread: *mut core::ffi::c_void) -> i32 {
    0 // THREAD_PRIORITY_NORMAL
}

/// SuspendThread - suspends the specified thread
/// Thread suspension is not implemented; all threads continue executing.
/// Returns 0 (previous suspend count of 0).
/// # Safety
/// `thread` is accepted as an opaque handle; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SuspendThread(_thread: *mut core::ffi::c_void) -> u32 {
    0 // previous suspend count
}

/// ResumeThread - decrements a thread's suspend count
/// Thread suspension is not implemented. Returns 0 (previous suspend count).
/// # Safety
/// `thread` is accepted as an opaque handle; it is not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ResumeThread(_thread: *mut core::ffi::c_void) -> u32 {
    0 // previous suspend count
}

/// OpenThread - opens an existing thread object
/// Returns a handle for threads managed in THREAD_HANDLES if the thread ID
/// matches the handle value; otherwise returns NULL with ERROR_INVALID_PARAMETER.
/// # Safety
/// `thread_id` is a thread identifier previously returned by CreateThread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OpenThread(
    _desired_access: u32,
    _inherit_handle: i32,
    thread_id: u32,
) -> *mut core::ffi::c_void {
    // Thread IDs in our implementation are the lower 32 bits of the handle value.
    // Reconstruct the handle value and check if it's in our registry.
    let handle_val = thread_id as usize;
    let exists = with_thread_handles(|map| map.contains_key(&handle_val));
    if exists {
        handle_val as *mut core::ffi::c_void
    } else {
        // SAFETY: no pointers are dereferenced.
        unsafe { kernel32_SetLastError(87) }; // ERROR_INVALID_PARAMETER
        core::ptr::null_mut()
    }
}

/// GetExitCodeThread - retrieves the termination status of the specified thread
/// Returns TRUE and fills `exit_code` with STILL_ACTIVE (259) if the thread is
/// still running, or with the actual exit code if it has finished.
/// # Safety
/// `exit_code` must point to a writable u32, or be null.
/// # Panics
/// Panics if the internal thread-handle mutex is poisoned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetExitCodeThread(
    thread: *mut core::ffi::c_void,
    exit_code: *mut u32,
) -> i32 {
    let handle_val = thread as usize;
    let code =
        with_thread_handles(|map| map.get(&handle_val).map(|e| *e.exit_code.lock().unwrap()));
    let value = match code {
        Some(Some(c)) => c,
        Some(None) => 259, // STILL_ACTIVE
        None => {
            // SAFETY: no pointers are dereferenced.
            unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
            return 0;
        }
    };
    if !exit_code.is_null() {
        // SAFETY: exit_code is checked non-null above.
        unsafe { *exit_code = value };
    }
    1 // TRUE
}

// ── Phase 27: Process Management ─────────────────────────────────────────────

/// OpenProcess - opens an existing local process object
///
/// Returns a pseudo-handle for the current process if `process_id` matches
/// the current PID.  If `process_id` matches a child process spawned by
/// `CreateProcessW`, the corresponding synthetic process handle is returned.
/// Otherwise returns NULL and sets `ERROR_INVALID_PARAMETER`.
///
/// # Safety
/// All arguments are accepted as values; none are dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OpenProcess(
    _desired_access: u32,
    _inherit_handle: i32,
    process_id: u32,
) -> *mut core::ffi::c_void {
    if process_id == std::process::id() {
        // Return pseudo-handle for current process (matches GetCurrentProcess)
        return usize::MAX as *mut core::ffi::c_void;
    }
    // Check if this PID belongs to a known child process.
    let found_handle = with_process_handles(|map| {
        map.iter()
            .find(|(_, e)| e.pid == process_id && e.is_process)
            .map(|(&h, _)| h)
    });
    if let Some(h) = found_handle {
        return h as *mut core::ffi::c_void;
    }
    // SAFETY: no pointers are dereferenced.
    unsafe { kernel32_SetLastError(87) }; // ERROR_INVALID_PARAMETER
    core::ptr::null_mut()
}

/// GetProcessTimes - retrieves timing information for the specified process
/// Returns current wall-clock time as creation time and zeros for CPU times.
/// # Safety
/// Output pointers must each be null or point to a valid FileTime (8 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessTimes(
    _process: *mut core::ffi::c_void,
    creation_time: *mut FileTime,
    exit_time: *mut FileTime,
    kernel_time: *mut FileTime,
    user_time: *mut FileTime,
) -> i32 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid out-pointer for clock_gettime.
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut ts) };
    // Convert Unix time to Windows FILETIME (100-ns intervals since 1601-01-01).
    // Use wrapping arithmetic to make overflow behavior explicit.
    let unix_100ns = (ts.tv_sec as u64)
        .wrapping_add(EPOCH_DIFF as u64)
        .wrapping_mul(10_000_000)
        .wrapping_add(ts.tv_nsec as u64 / 100);
    let ft = FileTime {
        low_date_time: unix_100ns as u32,
        high_date_time: (unix_100ns >> 32) as u32,
    };
    if !creation_time.is_null() {
        // SAFETY: creation_time is checked non-null.
        unsafe { *creation_time = ft };
    }
    if !exit_time.is_null() {
        // SAFETY: exit_time is checked non-null.
        unsafe {
            *exit_time = FileTime {
                low_date_time: 0,
                high_date_time: 0,
            }
        };
    }
    if !kernel_time.is_null() {
        // SAFETY: kernel_time is checked non-null.
        unsafe {
            *kernel_time = FileTime {
                low_date_time: 0,
                high_date_time: 0,
            }
        };
    }
    if !user_time.is_null() {
        // SAFETY: user_time is checked non-null.
        unsafe {
            *user_time = FileTime {
                low_date_time: 0,
                high_date_time: 0,
            }
        };
    }
    1 // TRUE
}

// ── Phase 39: Extended Process Management ────────────────────────────────────

/// Priority class constants (Windows)
const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;

/// GetPriorityClass — retrieves the priority class of the specified process.
///
/// In the sandboxed single-process environment, every handle is treated as the
/// current process and `NORMAL_PRIORITY_CLASS` (0x20) is always returned.
/// An unknown (null) handle returns 0 and sets `ERROR_INVALID_HANDLE` (6).
///
/// # Safety
/// `process` is accepted as an opaque value; it is never dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetPriorityClass(process: *mut core::ffi::c_void) -> u32 {
    if process.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0;
    }
    NORMAL_PRIORITY_CLASS
}

/// SetPriorityClass — sets the priority class of the specified process.
///
/// In the sandboxed single-process environment, the request is accepted and
/// ignored for the current-process pseudo-handle. Returns TRUE on success,
/// FALSE for a null handle.
///
/// # Safety
/// `process` is accepted as an opaque value; it is never dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetPriorityClass(
    process: *mut core::ffi::c_void,
    _priority_class: u32,
) -> i32 {
    if process.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    1 // TRUE
}

/// GetProcessAffinityMask — retrieves the process-affinity mask and system-affinity mask.
///
/// Sets both output masks to the set of logical CPUs available to the process
/// (queried via `sched_getaffinity`). If the query fails, a single-CPU mask is
/// returned. Returns TRUE on success.
///
/// # Safety
/// `process_affinity_mask` and `system_affinity_mask` (when non-null) must each
/// point to a writable `usize`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetProcessAffinityMask(
    _process: *mut core::ffi::c_void,
    process_affinity_mask: *mut usize,
    system_affinity_mask: *mut usize,
) -> i32 {
    let mut cpu_set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    let mask: usize = if unsafe {
        libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw mut cpu_set)
    } == 0
    {
        // Build a bitmask from the CPU set (up to usize bits).
        let bits = usize::BITS as usize;
        (0..bits).fold(0usize, |acc, i| {
            if unsafe { libc::CPU_ISSET(i, &cpu_set) } {
                acc | (1usize << i)
            } else {
                acc
            }
        })
    } else {
        1usize // fallback: single CPU
    };
    if !process_affinity_mask.is_null() {
        // SAFETY: caller guarantees the pointer is valid.
        unsafe { *process_affinity_mask = mask };
    }
    if !system_affinity_mask.is_null() {
        // SAFETY: caller guarantees the pointer is valid.
        unsafe { *system_affinity_mask = mask };
    }
    1 // TRUE
}

/// SetProcessAffinityMask — sets a processor-affinity mask for the threads of the process.
///
/// In the sandboxed environment the request is silently accepted and TRUE is
/// returned; no actual affinity change is applied.
///
/// # Safety
/// `process` is accepted as an opaque value; it is never dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetProcessAffinityMask(
    process: *mut core::ffi::c_void,
    _affinity_mask: usize,
) -> i32 {
    if process.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    1 // TRUE
}

/// FlushInstructionCache — flushes the instruction cache for the specified process.
///
/// On Linux/x86-64 no explicit instruction-cache flush is needed because
/// the CPU maintains coherency between data writes and instruction fetches.
/// The call is therefore a no-op that always returns TRUE.
///
/// # Safety
/// `process` and `base_address` are accepted as opaque values; neither is
/// dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlushInstructionCache(
    _process: *mut core::ffi::c_void,
    _base_address: *const core::ffi::c_void,
    _size: usize,
) -> i32 {
    1 // TRUE – x86-64 cache coherency makes this a no-op
}

/// ReadProcessMemory — reads memory in the specified process.
///
/// Only the current-process pseudo-handle (returned by `GetCurrentProcess()`)
/// is supported. For that handle, a plain `memcpy` from `base_address` into
/// `buffer` is performed.  `ERROR_ACCESS_DENIED` (5) is set and FALSE is
/// returned for any other handle or for null/zero-size arguments.
///
/// # Safety
/// `base_address` must be valid for `size` bytes of reading and `buffer` must
/// be valid for `size` bytes of writing when `process` is the current-process
/// pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_ReadProcessMemory(
    process: *mut core::ffi::c_void,
    base_address: *const core::ffi::c_void,
    buffer: *mut core::ffi::c_void,
    size: usize,
    bytes_read: *mut usize,
) -> i32 {
    let current = unsafe { kernel32_GetCurrentProcess() };
    if process != current || base_address.is_null() || buffer.is_null() || size == 0 {
        // SAFETY: no pointer is dereferenced here.
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED
        return 0; // FALSE
    }
    // SAFETY: caller guarantees both pointers are valid for `size` bytes.
    // Use copy (memmove semantics) rather than copy_nonoverlapping to handle
    // the case where source and destination overlap within the same process.
    unsafe { core::ptr::copy(base_address.cast::<u8>(), buffer.cast::<u8>(), size) };
    if !bytes_read.is_null() {
        // SAFETY: caller guarantees bytes_read is valid.
        unsafe { *bytes_read = size };
    }
    1 // TRUE
}

/// WriteProcessMemory — writes memory in the specified process.
///
/// Only the current-process pseudo-handle is supported; a plain `memcpy` from
/// `buffer` into `base_address` is performed. `ERROR_ACCESS_DENIED` (5) is set
/// and FALSE returned for any other handle or for null/zero-size arguments.
///
/// # Safety
/// `buffer` must be valid for `size` bytes of reading and `base_address` must
/// be valid for `size` bytes of writing when `process` is the current-process
/// pseudo-handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_WriteProcessMemory(
    process: *mut core::ffi::c_void,
    base_address: *mut core::ffi::c_void,
    buffer: *const core::ffi::c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    let current = unsafe { kernel32_GetCurrentProcess() };
    if process != current || base_address.is_null() || buffer.is_null() || size == 0 {
        // SAFETY: no pointer is dereferenced here.
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED
        return 0; // FALSE
    }
    // SAFETY: caller guarantees both pointers are valid for `size` bytes.
    // Use copy (memmove semantics) rather than copy_nonoverlapping to handle
    // the case where source and destination overlap within the same process.
    unsafe { core::ptr::copy(buffer.cast::<u8>(), base_address.cast::<u8>(), size) };
    if !bytes_written.is_null() {
        // SAFETY: caller guarantees bytes_written is valid.
        unsafe { *bytes_written = size };
    }
    1 // TRUE
}

/// VirtualAllocEx — reserves, commits, or changes the state of a region of
/// memory within the virtual address space of a specified process.
///
/// Only the current-process pseudo-handle is supported; the call is forwarded
/// to `VirtualAlloc`. For any other handle, NULL is returned and
/// `ERROR_ACCESS_DENIED` (5) is set.
///
/// # Safety
/// See `kernel32_VirtualAlloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualAllocEx(
    process: *mut core::ffi::c_void,
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    allocation_type: u32,
    protect: u32,
) -> *mut core::ffi::c_void {
    let current = unsafe { kernel32_GetCurrentProcess() };
    if process != current {
        // SAFETY: no pointer is dereferenced here.
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED
        return core::ptr::null_mut();
    }
    // SAFETY: delegates to kernel32_VirtualAlloc with the same safety contract.
    unsafe { kernel32_VirtualAlloc(lp_address, dw_size, allocation_type, protect) }
}

/// VirtualFreeEx — releases or decommits a region of memory within the virtual
/// address space of a specified process.
///
/// Only the current-process pseudo-handle is supported; the call is forwarded
/// to `VirtualFree`. For any other handle, FALSE is returned and
/// `ERROR_ACCESS_DENIED` (5) is set.
///
/// # Safety
/// See `kernel32_VirtualFree`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_VirtualFreeEx(
    process: *mut core::ffi::c_void,
    lp_address: *mut core::ffi::c_void,
    dw_size: usize,
    dw_free_type: u32,
) -> i32 {
    let current = unsafe { kernel32_GetCurrentProcess() };
    if process != current {
        // SAFETY: no pointer is dereferenced here.
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED
        return 0; // FALSE
    }
    // SAFETY: delegates to kernel32_VirtualFree with the same safety contract.
    unsafe { kernel32_VirtualFree(lp_address, dw_size, dw_free_type) }
}

/// Fake job-object handle value.
/// Using a sentinel in a high, reserved range avoids collisions with real
/// handles, which are allocated from monotonically increasing counters.
const JOB_OBJECT_HANDLE: usize = usize::MAX - 0x10;

/// CreateJobObjectW — creates or opens a job object.
///
/// In the sandboxed environment, process isolation via job objects is not
/// supported; a non-null pseudo-handle is returned so callers do not treat
/// the result as a failure, but no real job is created.
///
/// # Safety
/// `job_attributes` and `name` are accepted as opaque pointers; neither is
/// dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateJobObjectW(
    _job_attributes: *mut core::ffi::c_void,
    _name: *const u16,
) -> *mut core::ffi::c_void {
    JOB_OBJECT_HANDLE as *mut core::ffi::c_void
}

/// AssignProcessToJobObject — assigns a process to an existing job object.
///
/// In the sandboxed environment, only our pseudo-handle is recognised.
/// The call is silently accepted and TRUE is returned for it; for anything
/// else FALSE and `ERROR_INVALID_HANDLE` (6) are returned.
///
/// # Safety
/// `job` and `process` are accepted as opaque pointers; neither is dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_AssignProcessToJobObject(
    job: *mut core::ffi::c_void,
    process: *mut core::ffi::c_void,
) -> i32 {
    if job as usize != JOB_OBJECT_HANDLE || process.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    1 // TRUE
}

/// IsProcessInJob — determines whether the process is running in the specified job.
///
/// In the sandboxed environment, processes are never placed in a real job
/// object. The output is set to FALSE and TRUE (function success) is returned.
/// For null arguments, FALSE is returned and `ERROR_INVALID_PARAMETER` (87) is set.
///
/// # Safety
/// `result` (when non-null) must point to a writable `i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_IsProcessInJob(
    process: *mut core::ffi::c_void,
    _job: *mut core::ffi::c_void,
    result: *mut i32,
) -> i32 {
    if process.is_null() || result.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(87) }; // ERROR_INVALID_PARAMETER
        return 0; // FALSE
    }
    // SAFETY: caller guarantees result is a valid writable pointer.
    unsafe { *result = 0 }; // FALSE – not in a job
    1 // TRUE (function succeeded)
}

/// QueryInformationJobObject — retrieves limit and state information from a job object.
///
/// Returns a zeroed-out information block for the supported `JobObjectBasicAccountingInformation`
/// (class 1) and `JobObjectExtendedLimitInformation` (class 9) classes.
/// For unsupported classes, FALSE is returned and `ERROR_NOT_SUPPORTED` (50) is set.
///
/// # Safety
/// `job_object_information` (when non-null) must point to `job_object_information_length`
/// bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_QueryInformationJobObject(
    _job: *mut core::ffi::c_void,
    job_object_information_class: i32,
    job_object_information: *mut core::ffi::c_void,
    job_object_information_length: u32,
    return_length: *mut u32,
) -> i32 {
    // Classes we can answer with an all-zeroes struct:
    // 1 = JobObjectBasicAccountingInformation (48 bytes)
    // 9 = JobObjectExtendedLimitInformation (144 bytes on x86-64:
    //     64-byte JOBOBJECT_BASIC_LIMIT_INFORMATION +
    //     48-byte IO_COUNTERS + 4 × SIZE_T memory fields)
    let min_size: u32 = match job_object_information_class {
        1 => 48,
        9 => 144,
        _ => {
            // SAFETY: no pointer is dereferenced.
            unsafe { kernel32_SetLastError(50) }; // ERROR_NOT_SUPPORTED
            return 0; // FALSE
        }
    };
    if job_object_information_length < min_size || job_object_information.is_null() {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(24) }; // ERROR_BAD_LENGTH
        return 0; // FALSE
    }
    // SAFETY: caller guarantees the buffer is valid for job_object_information_length bytes.
    unsafe {
        core::ptr::write_bytes(
            job_object_information.cast::<u8>(),
            0,
            job_object_information_length as usize,
        );
    };
    if !return_length.is_null() {
        // SAFETY: caller guarantees return_length is valid.
        unsafe { *return_length = min_size };
    }
    1 // TRUE
}

/// SetInformationJobObject — sets limits for a job object.
///
/// In the sandboxed environment, job-object limits cannot actually be applied.
/// The call is silently accepted for our pseudo-handle and TRUE is returned.
///
/// # Safety
/// `job` and `job_object_information` are accepted as opaque pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetInformationJobObject(
    job: *mut core::ffi::c_void,
    _job_object_information_class: i32,
    _job_object_information: *mut core::ffi::c_void,
    _job_object_information_length: u32,
) -> i32 {
    if job as usize != JOB_OBJECT_HANDLE {
        // SAFETY: no pointer is dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0; // FALSE
    }
    1 // TRUE
}

/// OpenJobObjectW — opens an existing named job object.
///
/// Named job objects are not supported in the sandboxed environment.
/// NULL is returned and `ERROR_NOT_SUPPORTED` (50) is set.
///
/// # Safety
/// `name` is accepted as an opaque pointer; it is never dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_OpenJobObjectW(
    _desired_access: u32,
    _inherit_handle: i32,
    _name: *const u16,
) -> *mut core::ffi::c_void {
    // SAFETY: no pointer is dereferenced.
    unsafe { kernel32_SetLastError(50) }; // ERROR_NOT_SUPPORTED
    core::ptr::null_mut()
}

// ── Phase 43: Volume enumeration ─────────────────────────────────────────────

/// `FindFirstVolumeW` — returns a pseudo-handle for enumerating volumes.
///
/// On Linux there are no Windows volumes.  This stub returns a sentinel handle
/// (0x1) and writes a single synthetic volume GUID path `\\?\Volume{00000000-0000-0000-0000-000000000000}\`
/// into `volume_name`.  The handle must be closed with `FindVolumeClose`.
///
/// # Safety
/// `volume_name` must be valid for `buffer_length` `u16` elements of writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindFirstVolumeW(
    volume_name: *mut u16,
    buffer_length: u32,
) -> *mut core::ffi::c_void {
    const VOLUME_PATH: &str = "\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
    let wide: Vec<u16> = VOLUME_PATH
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();
    if !volume_name.is_null() && (buffer_length as usize) >= wide.len() {
        // SAFETY: volume_name is valid for buffer_length u16 elements; wide.len() <= buffer_length.
        unsafe {
            core::ptr::copy_nonoverlapping(wide.as_ptr(), volume_name, wide.len());
        }
    } else if !volume_name.is_null() {
        // Buffer too small — set ERROR_FILENAME_EXCED_RANGE and return INVALID_HANDLE_VALUE.
        unsafe { kernel32_SetLastError(206) }; // ERROR_FILENAME_EXCED_RANGE
        return usize::MAX as *mut core::ffi::c_void;
    }
    // Return a non-null sentinel handle meaning "one volume enumerated".
    core::ptr::dangling_mut::<core::ffi::c_void>()
}

/// `FindNextVolumeW` — advances to the next volume in the enumeration.
///
/// This stub has only one synthetic volume, so it always sets
/// `ERROR_NO_MORE_FILES` (18) and returns 0.
///
/// # Safety
/// `find_volume` must be a handle returned by `FindFirstVolumeW`.
/// `volume_name` must be valid for `buffer_length` `u16` elements of writes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindNextVolumeW(
    _find_volume: *mut core::ffi::c_void,
    _volume_name: *mut u16,
    _buffer_length: u32,
) -> i32 {
    // SAFETY: no pointer is dereferenced.
    unsafe { kernel32_SetLastError(18) }; // ERROR_NO_MORE_FILES
    0
}

/// `FindVolumeClose` — closes a volume-search handle.
///
/// Always returns 1 (success).
///
/// # Safety
/// `find_volume` must be a handle returned by `FindFirstVolumeW`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FindVolumeClose(_find_volume: *mut core::ffi::c_void) -> i32 {
    1
}

/// `GetVolumePathNamesForVolumeNameW` — returns mount-point paths for a volume.
///
/// Returns a double-NUL terminated list of wide-string paths.  This stub always
/// returns a single root path `\`.
///
/// # Safety
/// `buf` must point to `buf_len` u16-sized slots (or be null with `buf_len == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetVolumePathNamesForVolumeNameW(
    _volume_name: *const u16,
    buf: *mut u16,
    buf_len: u32,
    ret_len: *mut u32,
) -> i32 {
    // Single path: `\` encoded as one u16 (0x005c) + two NUL terminators.
    let needed: u32 = 3; // 1 char + 2 NUL words
    if !ret_len.is_null() {
        // SAFETY: ret_len is non-null per check above.
        unsafe { ret_len.write(needed) };
    }
    if buf_len < needed || buf.is_null() {
        kernel32_SetLastError(234); // ERROR_MORE_DATA
        return 0;
    }
    // SAFETY: buf has at least `buf_len` u16 slots per caller's contract.
    unsafe {
        buf.write(0x005c); // backslash
        buf.add(1).write(0);
        buf.add(2).write(0);
    }
    1
}

// ── Phase 27: File Times ──────────────────────────────────────────────────────

/// GetFileTime - retrieves the date and time a file or directory was created, last accessed, and last written
/// Reads the file's metadata via `fstat` to obtain actual timestamps.
/// # Safety
/// `file` must be a valid handle returned by `CreateFileW`. Output pointers
/// must each be null or point to at least 8 bytes of writable memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileTime(
    file: *mut core::ffi::c_void,
    creation_time: *mut FileTime,
    last_access_time: *mut FileTime,
    last_write_time: *mut FileTime,
) -> i32 {
    use std::os::unix::io::AsRawFd as _;
    let handle_val = file as usize;
    let fd = with_file_handles(|map| map.get(&handle_val).map(|e| e.file.as_raw_fd()));
    let Some(fd) = fd else {
        // SAFETY: no pointers are dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0;
    };
    let mut stat: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fd is a valid file descriptor; stat is a valid out-pointer.
    if unsafe { libc::fstat(fd, &raw mut stat) } != 0 {
        // SAFETY: no pointers are dereferenced.
        unsafe { kernel32_SetLastError(6) }; // ERROR_INVALID_HANDLE
        return 0;
    }
    let unix_to_filetime = |sec: i64, nsec: i64| -> FileTime {
        // Add EPOCH_DIFF in i64 to avoid overflow on pre-epoch dates; clamp to 0 if before 1601.
        let adjusted = sec.saturating_add(EPOCH_DIFF).max(0) as u64;
        let intervals = adjusted * 10_000_000 + nsec.max(0) as u64 / 100;
        FileTime {
            low_date_time: intervals as u32,
            high_date_time: (intervals >> 32) as u32,
        }
    };
    let write_ft = unix_to_filetime(stat.st_mtime, stat.st_mtime_nsec);
    let access_ft = unix_to_filetime(stat.st_atime, stat.st_atime_nsec);
    // Linux doesn't store true creation time; use ctime (metadata change) as approximation
    let create_ft = unix_to_filetime(stat.st_ctime, stat.st_ctime_nsec);
    if !creation_time.is_null() {
        // SAFETY: creation_time is checked non-null.
        unsafe { *creation_time = create_ft };
    }
    if !last_access_time.is_null() {
        // SAFETY: last_access_time is checked non-null.
        unsafe { *last_access_time = access_ft };
    }
    if !last_write_time.is_null() {
        // SAFETY: last_write_time is checked non-null.
        unsafe { *last_write_time = write_ft };
    }
    1 // TRUE
}

/// CompareFileTime - compares two file times
/// Returns -1 if first < second, 0 if equal, +1 if first > second.
/// # Safety
/// Both pointers must point to valid FileTime structures (8 bytes each).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CompareFileTime(
    file_time1: *const FileTime,
    file_time2: *const FileTime,
) -> i32 {
    if file_time1.is_null() || file_time2.is_null() {
        return 0;
    }
    // SAFETY: Both pointers are checked non-null above.
    let ft1 = unsafe { &*file_time1 };
    let ft2 = unsafe { &*file_time2 };
    let v1 = u64::from(ft1.low_date_time) | (u64::from(ft1.high_date_time) << 32);
    let v2 = u64::from(ft2.low_date_time) | (u64::from(ft2.high_date_time) << 32);
    match v1.cmp(&v2) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    }
}

/// FileTimeToLocalFileTime - converts a UTC file time to a local file time
/// Applies the local timezone offset to the FILETIME value.
/// # Safety
/// Both pointers must point to valid FileTime structures (8 bytes each).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FileTimeToLocalFileTime(
    utc_file_time: *const FileTime,
    local_file_time: *mut FileTime,
) -> i32 {
    if utc_file_time.is_null() || local_file_time.is_null() {
        return 0;
    }
    // SAFETY: Pointers are checked non-null above.
    let ft = unsafe { &*utc_file_time };
    let intervals = u64::from(ft.low_date_time) | (u64::from(ft.high_date_time) << 32);
    let unix_time = (intervals / 10_000_000) as i64 - EPOCH_DIFF;
    let mut tm_local: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: unix_time is a valid time_t value; tm_local is a valid out-pointer.
    unsafe { libc::localtime_r(&raw const unix_time, &raw mut tm_local) };
    // offset_sec is bounded to ±50400 seconds (±14 hours); multiply by 10M to get
    // 100-ns intervals, then add to the UTC intervals using signed arithmetic
    // to correctly handle negative (west-of-UTC) offsets.
    let offset_100ns = tm_local.tm_gmtoff.saturating_mul(10_000_000);
    let local_intervals = (intervals as i64).saturating_add(offset_100ns).max(0) as u64;
    // SAFETY: local_file_time is checked non-null above.
    unsafe {
        (*local_file_time).low_date_time = local_intervals as u32;
        (*local_file_time).high_date_time = (local_intervals >> 32) as u32;
    }
    1 // TRUE
}

// ── Phase 27: Temp File Name ──────────────────────────────────────────────────

/// GetTempFileNameW - creates a name for a temporary file
/// Creates a unique temp file name in the specified path with the given prefix
/// and a numeric suffix. Returns the number of characters in the name.
/// # Safety
/// `path_name` must be a valid null-terminated wide string.
/// `prefix_string` must be a valid null-terminated wide string, or null.
/// `temp_file_name` must point to at least MAX_PATH (260) wide characters.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetTempFileNameW(
    path_name: *const u16,
    prefix_string: *const u16,
    unique: u32,
    temp_file_name: *mut u16,
) -> u32 {
    if path_name.is_null() || temp_file_name.is_null() {
        // SAFETY: no pointers are dereferenced.
        unsafe { kernel32_SetLastError(87) }; // ERROR_INVALID_PARAMETER
        return 0;
    }
    // SAFETY: path_name is checked non-null; caller guarantees valid null-terminated wide string.
    let path = unsafe { wide_str_to_string(path_name) };
    let prefix = if prefix_string.is_null() {
        "tmp".to_string()
    } else {
        // SAFETY: prefix_string is checked non-null; caller guarantees valid null-terminated wide string.
        let p = unsafe { wide_str_to_string(prefix_string) };
        p.chars().take(3).collect::<String>()
    };
    let unique_val = if unique != 0 {
        unique
    } else {
        // SAFETY: GetTickCount64 does not dereference any pointer.
        (unsafe { kernel32_GetTickCount64() } & 0xFFFF) as u32
    };
    let sep = if path.ends_with('\\') || path.ends_with('/') {
        ""
    } else {
        "\\"
    };
    let file_name = format!("{path}{sep}{prefix}{unique_val:04x}.tmp");
    let wide: Vec<u16> = file_name.encode_utf16().collect();
    let copy_len = wide.len().min(259); // MAX_PATH - 1
    // SAFETY: temp_file_name must hold at least 260 wide chars; we copy at most 259 + null.
    unsafe {
        core::ptr::copy_nonoverlapping(wide.as_ptr(), temp_file_name, copy_len);
        *temp_file_name.add(copy_len) = 0;
    }
    copy_len as u32
}

// ── Phase 28: File utility additions ─────────────────────────────────────

/// GetFileSize - get the size of a file as a 32-bit DWORD pair
///
/// Returns the low-order DWORD of the file size. Optionally sets `lp_file_size_high`.
/// Returns `INVALID_FILE_SIZE` (0xFFFF_FFFF) on error.
///
/// # Safety
/// `file` must be a valid file handle; `lp_file_size_high` if non-null must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetFileSize(
    file: *mut core::ffi::c_void,
    lp_file_size_high: *mut u32,
) -> u32 {
    let mut size: i64 = 0;
    if kernel32_GetFileSizeEx(file, &raw mut size) == 0 {
        return 0xFFFF_FFFF; // INVALID_FILE_SIZE
    }
    let size_u = size as u64;
    if !lp_file_size_high.is_null() {
        *lp_file_size_high = (size_u >> 32) as u32;
    }
    (size_u & 0xFFFF_FFFF) as u32
}

/// SetFilePointer - moves the file pointer (32-bit interface)
///
/// Combines `distance_to_move` and `*distance_to_move_high` into a 64-bit offset,
/// then calls `SetFilePointerEx`. Returns the new low DWORD position, or
/// `INVALID_SET_FILE_POINTER` (0xFFFF_FFFF) on error.
///
/// # Safety
/// `file` must be a valid file handle; `distance_to_move_high` if non-null must be readable/writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetFilePointer(
    file: *mut core::ffi::c_void,
    distance_to_move: i32,
    distance_to_move_high: *mut i32,
    move_method: u32,
) -> u32 {
    let high = if distance_to_move_high.is_null() {
        0i64
    } else {
        i64::from(*distance_to_move_high)
    };
    let combined = (high << 32) | i64::from(distance_to_move as u32);
    let mut new_pos: i64 = 0;
    if kernel32_SetFilePointerEx(file, combined, &raw mut new_pos, move_method) == 0 {
        return 0xFFFF_FFFF; // INVALID_SET_FILE_POINTER
    }
    if !distance_to_move_high.is_null() {
        *distance_to_move_high = ((new_pos as u64) >> 32) as i32;
    }
    (new_pos as u64 & 0xFFFF_FFFF) as u32
}

/// SetEndOfFile - truncates or extends the file at the current file pointer position
///
/// Uses `ftruncate` with the current file position obtained from `lseek`.
/// Returns 1 (TRUE) on success, 0 (FALSE) on error.
///
/// # Safety
/// `file` must be a valid file handle opened for writing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_SetEndOfFile(file: *mut core::ffi::c_void) -> i32 {
    let handle_val = file as usize;
    let fd_and_pos = with_file_handles(|map| {
        map.get(&handle_val).map(|entry| {
            let fd = entry.file.as_raw_fd();
            // SAFETY: fd is valid for the duration of this closure
            let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
            (fd, pos)
        })
    });
    let Some((fd, pos)) = fd_and_pos else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };
    if pos < 0 {
        kernel32_SetLastError(6);
        return 0;
    }
    // SAFETY: fd is valid and pos is non-negative
    if unsafe { libc::ftruncate(fd, pos) } == 0 {
        1
    } else {
        kernel32_SetLastError(5); // ERROR_ACCESS_DENIED
        0
    }
}

/// FlushViewOfFile - flushes a range of mapped view to disk
///
/// Calls `msync(base_address, size, MS_SYNC)`. Returns 1 (TRUE) on success.
///
/// # Safety
/// `base_address` must be a valid pointer into a mapped view; must be readable for `number_of_bytes_to_flush` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_FlushViewOfFile(
    base_address: *const core::ffi::c_void,
    number_of_bytes_to_flush: usize,
) -> i32 {
    if base_address.is_null() {
        return 0;
    }
    let size = if number_of_bytes_to_flush == 0 {
        1
    } else {
        number_of_bytes_to_flush
    };
    // SAFETY: caller guarantees base_address is valid mapped memory
    i32::from(unsafe { libc::msync(base_address.cast_mut(), size, libc::MS_SYNC) } == 0)
}

/// GetSystemDefaultLangID - returns the system default language identifier
///
/// Always returns 0x0409 (English - United States) in this headless implementation.
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemDefaultLangID() -> u16 {
    0x0409
}

/// GetUserDefaultLangID - returns the user default language identifier
///
/// Always returns 0x0409 (English - United States) in this headless implementation.
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetUserDefaultLangID() -> u16 {
    0x0409
}

/// GetSystemDefaultLCID - returns the system default locale identifier
///
/// Always returns 0x0409 (English - United States) in this headless implementation.
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetSystemDefaultLCID() -> u32 {
    0x0409
}

/// GetUserDefaultLCID - returns the user default locale identifier
///
/// Always returns 0x0409 (English - United States) in this headless implementation.
///
/// # Safety
/// No preconditions.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetUserDefaultLCID() -> u32 {
    0x0409
}

// ── SEH helper: restore a Windows CONTEXT and jump to its RIP ──────────────

unsafe extern "C" {
    /// Restore all general-purpose registers from a Windows x64 CONTEXT and
    /// jump to `ctx->Rip` with `ctx->Rsp` as the stack pointer.
    ///
    /// The function is implemented in `global_asm!` below.  It never returns.
    ///
    /// # Safety
    /// `ctx` must point to a valid, readable Windows CONTEXT (≥ CTX_SIZE bytes)
    /// whose `Rip` and `Rsp` fields describe a valid landing pad.
    pub(crate) fn seh_restore_context_and_jump(ctx: *mut u8) -> !;
}

// Restores all GPRs from a Windows x64 CONTEXT struct (SysV calling convention:
// argument arrives in RDI).  The sequence is:
//   1. Switch RSP to the target stack (ctx->Rsp).
//   2. Push the target RIP onto the new stack.
//   3. Restore all remaining GPRs (RDI last, since it holds our ctx pointer).
//   4. RET — pops the target RIP and jumps there.
core::arch::global_asm!(
    ".globl seh_restore_context_and_jump",
    "seh_restore_context_and_jump:",
    // Switch to the target stack; push the target RIP so we can `ret` to it.
    "mov rsp, QWORD PTR [rdi + 0x98]", // ctx->Rsp  → rsp
    "push QWORD PTR [rdi + 0xF8]",     // ctx->Rip  → [rsp]
    // Restore GPRs (order does not matter except rdi must be last).
    "mov r15, QWORD PTR [rdi + 0xF0]",
    "mov r14, QWORD PTR [rdi + 0xE8]",
    "mov r13, QWORD PTR [rdi + 0xE0]",
    "mov r12, QWORD PTR [rdi + 0xD8]",
    "mov r11, QWORD PTR [rdi + 0xD0]",
    "mov r10, QWORD PTR [rdi + 0xC8]",
    "mov r9,  QWORD PTR [rdi + 0xC0]",
    "mov r8,  QWORD PTR [rdi + 0xB8]",
    "mov rsi, QWORD PTR [rdi + 0xA8]",
    "mov rbp, QWORD PTR [rdi + 0xA0]",
    "mov rbx, QWORD PTR [rdi + 0x90]",
    "mov rcx, QWORD PTR [rdi + 0x80]",
    "mov rdx, QWORD PTR [rdi + 0x88]",
    "mov rax, QWORD PTR [rdi + 0x78]",
    "mov rdi, QWORD PTR [rdi + 0xB0]", // clobbers ctx ptr – must be last
    "ret",
);

// ── SEH helper: scan the Rust stack for the first PE return address ─────────

/// Scan the Rust call stack upward from `rust_rsp` looking for the PE return
/// address that was pushed by the `call [IAT_func]` instruction inside the PE
/// (e.g. inside `_Unwind_RaiseException` when it calls `RaiseException`).
///
/// The trampoline that bridges Windows→Linux calling conventions has this
/// structure in its prologue (for a 4-parameter function):
///
/// ```text
/// [entry_rsp - 8]:  push rdi  (saves Windows param1)
/// [entry_rsp - 16]: push rsi  (saves Windows param2)
/// [entry_rsp - 24]: sub rsp,8 (alignment gap, nothing written)
/// [entry_rsp - 32]: call rax  → pushes trampoline return address
/// ```
///
/// So from current Rust RSP (after `sub rsp, rust_frame_size` prologue):
///
/// ```text
/// [rsp + rust_frame_size + 0]:  trampoline return addr  (NULL from pdata)
/// [rsp + rust_frame_size + 8]:  alignment gap
/// [rsp + rust_frame_size + 16]: saved rsi
/// [rsp + rust_frame_size + 24]: saved rdi
/// [rsp + rust_frame_size + 32]: PE return addr          (non-NULL from pdata)
/// ```
///
/// To distinguish the live trampoline frame from stale data, we validate
/// the first candidate by checking for the trampoline epilogue byte pattern
/// (`pop rsi; pop rdi; ret` = `5E 5F C3`), then use the **last** (highest-
/// offset) match since the actual trampoline frame sits directly above the
/// Rust frame while stale trampoline return addresses from earlier IAT calls
/// live at lower offsets inside the Rust frame body.
///
/// Returns a [`PeFrameInfo`] with the validated PE return address, guest RSP,
/// and the guest's saved RSI/RDI from the trampoline.
///
/// Information about a PE frame found on the stack.
struct PeFrameInfo {
    /// PC inside the PE function (return address from the PE's `call [IAT]`).
    control_pc: u64,
    /// Guest RSP at the PE call site (RSP before the `call [IAT]`).
    guest_rsp: u64,
    /// Guest RSI saved by the trampoline's prolog.
    guest_rsi: u64,
    /// Guest RDI saved by the trampoline's prolog.
    guest_rdi: u64,
}

fn seh_find_pe_frame_on_stack(rust_rsp: usize) -> Option<PeFrameInfo> {
    let pe_base = {
        let guard = EXCEPTION_TABLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tbl = (*guard).as_ref()?;
        tbl.image_base
    };

    // Scan upward from rust_rsp for trampoline frames.
    //
    // The call chain is:
    //   PE code → [call IAT] → trampoline → [call rax] → this Rust function
    //
    // We look for trampoline epilogue signatures at each slot, with a
    // valid .pdata PE return address 32 bytes above.
    //
    // We use the FIRST match (lowest offset) because the active trampoline
    // frame is the closest to our Rust RSP — it sits directly above the
    // Rust frames (kernel32_RaiseException → msvcrt__CxxThrowException →
    // trampoline → PE code).  Stale trampoline frames from earlier IAT
    // calls (e.g. printf called before the throw) reside at higher offsets
    // in the PE caller's frame area and would yield the wrong PE return
    // address.
    //
    // The window must be large enough to reach the trampoline frame even
    // when multiple Rust functions are between `kernel32_RaiseException`
    // and the trampoline (e.g. during a C++ rethrow that goes through
    // `cxx_handle_rethrow` → `msvcrt__CxxThrowException` → trampoline).
    for offset in (0..2048_usize).step_by(8) {
        if let Some(info) = try_trampoline_at_offset(rust_rsp, offset, pe_base) {
            return Some(info);
        }
    }

    None
}

/// Try to extract a PE frame from a specific stack offset.
///
/// Returns `Some(PeFrameInfo)` if `[rust_rsp + offset]` points to a
/// trampoline epilogue (`pop rsi; pop rdi; ret`) and
/// `[rust_rsp + offset + 32]` is a valid .pdata PE address.
#[allow(clippy::similar_names)]
fn try_trampoline_at_offset(rust_rsp: usize, offset: usize, pe_base: u64) -> Option<PeFrameInfo> {
    const PE_MAX_SIZE: u64 = 16 * 1024 * 1024;
    // Userspace address range: above the first 64KB (reserved by the OS)
    // and below the canonical address boundary on x86-64.
    const MIN_USERSPACE_ADDR: u64 = 0x10000;
    const MAX_USERSPACE_ADDR: u64 = 0x7FFF_FFFF_FFFF;
    // Trampoline epilogue: pop rsi; pop rdi; ret
    const TRAMPOLINE_EPILOGUE: [u8; 3] = [0x5E, 0x5F, 0xC3];

    #[inline]
    fn in_pe_range(addr: u64, pe_base: u64) -> bool {
        let rva = addr.wrapping_sub(pe_base);
        rva > 0x1000 && rva < PE_MAX_SIZE
    }

    // Ensure all reads within the trampoline frame stay inside the
    // scan window.  The largest read is a u64 at `slot + 32`,
    // which spans bytes [offset+32 .. offset+40).
    if offset + 40 > 2048 {
        return None;
    }

    let slot = rust_rsp + offset;
    // SAFETY: Reading from our own live call stack.
    let candidate = unsafe { (slot as *const u64).read_unaligned() };

    // The trampoline return address is in separately mmap'd trampoline
    // memory, NOT in the PE.  Validate it by checking for the trampoline
    // epilogue byte pattern.  The epilogue starts after an `add rsp, N`
    // instruction (4 or 7 bytes), so we scan the first 8 bytes.
    if !(MIN_USERSPACE_ADDR..=MAX_USERSPACE_ADDR).contains(&candidate) {
        return None;
    }
    // Check if the page at `candidate` is mapped using mincore().
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let page_addr = (candidate as usize) & !(page_size - 1);
    let mut vec: u8 = 0;
    let rc = unsafe { libc::mincore(page_addr as *mut libc::c_void, page_size, &raw mut vec) };
    if rc != 0 {
        // Page is not mapped — not a valid address.
        return None;
    }

    let tramp_ret = candidate as *const u8;
    let mut found_epilogue = false;
    for scan_offset in 0..8_usize {
        // SAFETY: We verified the page is mapped via mincore() above.
        let bytes = unsafe {
            [
                tramp_ret.add(scan_offset).read(),
                tramp_ret.add(scan_offset + 1).read(),
                tramp_ret.add(scan_offset + 2).read(),
            ]
        };
        if bytes == TRAMPOLINE_EPILOGUE {
            found_epilogue = true;
            break;
        }
    }
    if !found_epilogue {
        return None;
    }

    let pe_slot = slot + 32;
    let pe_candidate = unsafe { (pe_slot as *const u64).read_unaligned() };

    if !in_pe_range(pe_candidate, pe_base) {
        return None;
    }
    // SAFETY: pe_candidate is a valid PE address.
    if unsafe {
        kernel32_RtlLookupFunctionEntry(pe_candidate, core::ptr::null_mut(), core::ptr::null_mut())
            .is_null()
    } {
        return None;
    }

    // Extract saved RSI and RDI from the trampoline frame.
    // Layout: [slot+0]=tramp_ret, [slot+8]=padding, [slot+16]=saved RSI,
    //         [slot+24]=saved RDI, [slot+32]=PE return address
    let guest_rsi = unsafe { ((slot + 16) as *const u64).read_unaligned() };
    let guest_rdi = unsafe { ((slot + 24) as *const u64).read_unaligned() };

    Some(PeFrameInfo {
        control_pc: pe_candidate,
        guest_rsp: pe_slot as u64 + 8,
        guest_rsi,
        guest_rdi,
    })
}

// ── SEH helper: walk the PE call stack dispatching language handlers ─────────

/// Non-volatile register snapshot captured at `RaiseException` entry.
///
/// These registers are callee-saved across both the Windows x64 and SysV
/// calling conventions, so their values inside `kernel32_RaiseException`
/// reflect the guest PE's register state at the `call RaiseException` site.
struct NonVolatileRegs {
    rbx: u64,
    rbp: u64,
    rsi: u64,
    rdi: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

/// Read the UNWIND_INFO for a function and compute the body frame-pointer
/// register value.
///
/// Many Windows x64 functions set `UWOP_SET_FPREG` in their prolog, which
/// establishes a frame register (usually `RBP`) as:
///
/// ```text
/// frame_reg = body_RSP + frame_offset * 16
/// ```
///
/// This function reads the UNWIND_INFO header for the given RUNTIME_FUNCTION,
/// extracts `frame_register` and `frame_offset`, and returns
/// `Some((reg_offset, value))` when a frame register is used, or `None` if the
/// function does not set a frame register.
///
/// # Safety
/// `image_base` must be the PE's load address and `function_entry` must point
/// to a valid RUNTIME_FUNCTION within the image.
pub(crate) unsafe fn compute_body_frame_reg(
    image_base: u64,
    function_entry: *mut core::ffi::c_void,
    body_rsp: u64,
) -> Option<(usize, u64)> {
    /// Maximum plausible PE image size for RVA validation.
    const MAX_PE_IMAGE_SIZE: u64 = 64 * 1024 * 1024;

    if function_entry.is_null() || image_base == 0 {
        return None;
    }
    let rf = function_entry.cast::<u32>();
    // SAFETY: function_entry is a valid RUNTIME_FUNCTION (at least 12 bytes).
    let unwind_info_rva = unsafe { rf.add(2).read_unaligned() };
    // Reject obviously invalid RVAs (0 or exceeding any plausible PE size).
    if unwind_info_rva == 0 || u64::from(unwind_info_rva) > MAX_PE_IMAGE_SIZE {
        return None;
    }
    let ui = (image_base + u64::from(unwind_info_rva)) as *const u8;
    // SAFETY: image_base + unwind_info_rva is within the loaded image;
    // UNWIND_INFO is at least 4 bytes, so reading byte 3 is valid.
    let frame_reg_and_offset = unsafe { ui.add(3).read() };
    let frame_register = frame_reg_and_offset & 0x0F;
    let frame_offset = (frame_reg_and_offset >> 4) & 0x0F;
    if frame_register != 0 {
        let reg_off = ctx_reg_offset(frame_register);
        let value = body_rsp + u64::from(frame_offset) * 16;
        Some((reg_off, value))
    } else {
        None
    }
}

/// Walk the PE call stack starting at `(start_pc, start_sp)` and
/// dispatch language-specific exception handlers.
///
/// `phase`:
/// - `1` — search phase: calls `EHANDLER` routines without setting
///   `EXCEPTION_UNWINDING`.  Returns `true` as soon as a handler accepts
///   (i.e. calls `RtlUnwindEx`, which never returns here).
/// - `2` — cleanup phase: calls `UHANDLER` routines with `EXCEPTION_UNWINDING`
///   set in the exception record.  Returns `true` when the target frame is
///   reached (currently walks all frames).
///
/// Returns `false` if no more PE frames are found before a handler accepts.
///
/// # Safety
/// `exc_rec` must point to a valid, writable `ExceptionRecord`.
#[allow(clippy::similar_names)]
unsafe fn seh_walk_stack_dispatch(
    exc_rec: *mut ExceptionRecord,
    start_pc: u64,
    start_sp: u64,
    phase: u32,
    nv_regs: &NonVolatileRegs,
) -> bool {
    // Language handler function type (Windows x64 ABI).
    type ExceptionRoutine =
        unsafe extern "win64" fn(*mut ExceptionRecord, u64, *mut u8, *mut DispatcherContext) -> i32;

    // Allocate a CONTEXT on the heap (1232 bytes) — too large for the stack.
    let ctx_layout = alloc::Layout::from_size_align(CTX_SIZE, 16).expect("CTX layout is valid");
    // SAFETY: layout is non-zero.
    let ctx_ptr = unsafe { alloc::alloc_zeroed(ctx_layout) };
    if ctx_ptr.is_null() {
        return false;
    }

    // Seed the context with the guest's initial PC, SP, and non-volatile
    // registers.  These registers are callee-saved across the trampoline
    // and Rust frames, so they match the guest PE state at the throw site.
    // SAFETY: ctx_ptr is a freshly zeroed CTX_SIZE-byte allocation.
    unsafe {
        ctx_write(ctx_ptr, CTX_RIP, start_pc);
        ctx_write(ctx_ptr, CTX_RSP, start_sp);
        ctx_write(ctx_ptr, CTX_RBX, nv_regs.rbx);
        ctx_write(ctx_ptr, CTX_RBP, nv_regs.rbp);
        ctx_write(ctx_ptr, CTX_RSI, nv_regs.rsi);
        ctx_write(ctx_ptr, CTX_RDI, nv_regs.rdi);
        ctx_write(ctx_ptr, CTX_R12, nv_regs.r12);
        ctx_write(ctx_ptr, CTX_R13, nv_regs.r13);
        ctx_write(ctx_ptr, CTX_R14, nv_regs.r14);
        ctx_write(ctx_ptr, CTX_R15, nv_regs.r15);
    }

    let handler_flag = if phase == 2 {
        u32::from(UNW_FLAG_UHANDLER)
    } else {
        u32::from(UNW_FLAG_EHANDLER)
    };

    // Set EXCEPTION_UNWINDING on the record for phase-2 walks.
    if phase == 2 {
        // SAFETY: caller guarantees exc_rec is valid.
        unsafe { (*exc_rec).exception_flags |= EXCEPTION_UNWINDING };
    }

    let mut found = false;
    let mut max_frames: u32 = 256; // guard against infinite loops

    // Allocate a second CONTEXT buffer to save the pre-unwind state.
    // The language handler must receive the context as it was BEFORE
    // `RtlVirtualUnwind` modifies it (i.e. with the function body RSP,
    // not the caller's RSP).  Wine's `RtlDispatchException` does the same:
    // it passes the pre-unwind context to the handler while advancing a
    // separate copy.
    // SAFETY: layout is non-zero.
    let saved_ctx = unsafe { alloc::alloc_zeroed(ctx_layout) };
    if saved_ctx.is_null() {
        unsafe { alloc::dealloc(ctx_ptr, ctx_layout) };
        return false;
    }

    loop {
        max_frames -= 1;
        if max_frames == 0 {
            break;
        }

        // SAFETY: ctx_ptr is a valid CONTEXT.
        let control_pc = unsafe { ctx_read(ctx_ptr, CTX_RIP) };
        if control_pc == 0 {
            break;
        }

        let mut image_base: u64 = 0;
        // SAFETY: RtlLookupFunctionEntry is safe to call with a valid PC and
        // a pointer to a u64 output.
        let fe = unsafe {
            kernel32_RtlLookupFunctionEntry(control_pc, &raw mut image_base, core::ptr::null_mut())
        };
        if fe.is_null() {
            // No .pdata entry — this is either a leaf function (which doesn't
            // modify RSP or save non-volatile registers) or a non-PE address.
            // For leaf functions inside the PE: pop the return address from
            // RSP and continue the walk.  For addresses outside the PE: stop.
            let pe_base = {
                let guard = EXCEPTION_TABLE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (*guard).as_ref().map_or(0, |t| t.image_base)
            };
            let rva = control_pc.wrapping_sub(pe_base);
            if pe_base != 0 && rva > 0x1000 && rva < 16 * 1024 * 1024 {
                // Likely a leaf function inside the PE — pop return address.
                let rsp = unsafe { ctx_read(ctx_ptr, CTX_RSP) };
                let ret_addr = unsafe { (rsp as *const u64).read_unaligned() };
                unsafe {
                    ctx_write(ctx_ptr, CTX_RIP, ret_addr);
                    ctx_write(ctx_ptr, CTX_RSP, rsp + 8);
                }
                continue;
            }
            // Outside the PE — no more frames to walk.
            break;
        }

        let mut handler_data: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut establisher_frame: u64 = 0;

        // Save the pre-unwind context (function body state) before
        // `RtlVirtualUnwind` advances ctx_ptr to the caller's frame.
        // The handler needs the body RSP (before prolog unwind) so the
        // landing pad finds the correct stack layout.
        // SAFETY: both buffers are CTX_SIZE bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(ctx_ptr, saved_ctx, CTX_SIZE);
        }

        // SAFETY: fe and ctx_ptr are valid; establisher_frame and handler_data
        // are valid output slots.
        let lang_handler = unsafe {
            kernel32_RtlVirtualUnwind(
                handler_flag,
                image_base,
                control_pc,
                fe,
                ctx_ptr.cast::<core::ffi::c_void>(),
                &raw mut handler_data,
                &raw mut establisher_frame,
                core::ptr::null_mut(),
            )
        };

        if !lang_handler.is_null() {
            // The handler context must reflect the function BODY state (before
            // its prolog is unwound).  `saved_ctx` was copied from `ctx_ptr`
            // BEFORE `RtlVirtualUnwind` modified it, so it contains:
            //   - RSP/RIP: the function body values (correct)
            //   - Non-volatile registers: accumulated from the initial context
            //     plus all preceding unwinds.  Since the initial context was
            //     seeded with the guest's callee-saved registers (from the
            //     trampoline frame), and each unwind restores registers from
            //     the PE stack, `saved_ctx` has the correct function-entry
            //     register values for this frame.
            //
            // If the function sets a frame register via UWOP_SET_FPREG
            // (typically RBP), we recompute its body value from the body RSP
            // and the UNWIND_INFO header, since the prolog modifies it after
            // saving the caller's value.
            let body_rsp = unsafe { ctx_read(saved_ctx, CTX_RSP) };

            // If the function uses a frame register (e.g. RBP), recompute
            // its body value: frame_reg = body_RSP + frame_offset * 16.
            // SAFETY: image_base and fe are valid.
            if let Some((reg_off, val)) =
                unsafe { compute_body_frame_reg(image_base, fe, body_rsp) }
            {
                unsafe { ctx_write(saved_ctx, reg_off, val) };
            }

            // Build a DISPATCHER_CONTEXT for this frame.
            // Use saved_ctx (pre-unwind body context with corrected registers)
            // so the handler (and any `RtlUnwindEx` call it makes) sees the
            // function BODY RSP — not the caller's RSP.
            let mut dc = DispatcherContext {
                control_pc,
                image_base,
                function_entry: fe,
                establisher_frame,
                target_ip: 0,
                context_record: saved_ctx,
                language_handler: lang_handler,
                handler_data,
                history_table: core::ptr::null_mut(),
                scope_index: 0,
                _fill0: 0,
            };

            // Call the language handler using the Windows x64 ABI (win64).
            // The handler is a PE function; its four parameters are:
            //   rcx = ExceptionRecord*
            //   rdx = EstablisherFrame (u64)
            //   r8  = CONTEXT*
            //   r9  = DISPATCHER_CONTEXT*

            // SAFETY: lang_handler is a valid PE function pointer with the
            // EXCEPTION_ROUTINE signature.
            let handler_fn: ExceptionRoutine = unsafe { core::mem::transmute(lang_handler) };

            // Pass saved_ctx (pre-unwind body context) to the handler.
            // SAFETY: all pointers are valid for their respective types.
            let disposition =
                unsafe { handler_fn(exc_rec, establisher_frame, saved_ctx, &raw mut dc) };

            if disposition == EXCEPTION_CONTINUE_EXECUTION {
                found = true;
                break;
            }
            // EXCEPTION_CONTINUE_SEARCH (1): keep walking.
            // If the handler itself called RtlUnwindEx, we never reach here.
        }
        // Context has been updated by RtlVirtualUnwind to the caller's frame;
        // the next iteration processes the caller.
    }

    // SAFETY: ctx_ptr and saved_ctx were allocated above with ctx_layout.
    unsafe {
        alloc::dealloc(ctx_ptr, ctx_layout);
        alloc::dealloc(saved_ctx, ctx_layout);
    }
    found
}

// ── IOCP API ────────────────────────────────────────────────────────────────

/// CreateIoCompletionPort - creates an I/O completion port, or associates a
/// file handle with an existing I/O completion port.
///
/// When `file_handle` is `INVALID_HANDLE_VALUE` (-1 as isize), a new
/// completion port is created and its handle is returned.
///
/// When `file_handle` is a regular file handle, it is associated with the
/// port identified by `existing_completion_port` using `completion_key`.
/// Subsequent overlapped `ReadFile`/`WriteFile` operations on the file will
/// post a completion packet to the port.  The existing port handle is
/// returned on success.
///
/// Returns NULL on failure.
///
/// # Safety
/// `file_handle` and `existing_completion_port` must be valid handles or
/// the sentinel `INVALID_HANDLE_VALUE`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_CreateIoCompletionPort(
    file_handle: *mut core::ffi::c_void,
    existing_completion_port: *mut core::ffi::c_void,
    completion_key: usize,
    _number_of_concurrent_threads: u32,
) -> *mut core::ffi::c_void {
    let is_invalid = file_handle as isize == -1;

    if is_invalid {
        // Create a new I/O completion port.
        let handle = alloc_iocp_handle();
        let entry = IocpEntry {
            state: Arc::new((
                Mutex::new(IocpSharedState {
                    queue: VecDeque::new(),
                }),
                Condvar::new(),
            )),
        };
        with_iocp_handles(|map| {
            map.insert(handle, entry);
        });
        return handle as *mut core::ffi::c_void;
    }

    // Associate an existing file handle with a completion port.
    let port_val = existing_completion_port as usize;
    let file_val = file_handle as usize;

    // Verify the port exists.
    let port_exists = with_iocp_handles(|map| map.contains_key(&port_val));
    if !port_exists {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return core::ptr::null_mut();
    }

    // Record the IOCP association in the file entry.
    let associated = with_file_handles(|map| {
        if let Some(entry) = map.get_mut(&file_val) {
            entry.iocp_handle = port_val;
            entry.completion_key = completion_key;
            true
        } else {
            false
        }
    });

    if associated {
        existing_completion_port
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        core::ptr::null_mut()
    }
}

/// PostQueuedCompletionStatus - posts an I/O completion packet to an I/O
/// completion port.
///
/// Enqueues a completion packet with the supplied `bytes_transferred`,
/// `completion_key`, and `overlapped` pointer.  Any thread blocked in
/// `GetQueuedCompletionStatus` waiting on this port will be woken.
///
/// Returns TRUE on success, FALSE if the port handle is invalid.
///
/// # Safety
/// `completion_port` must be a valid IOCP handle returned by
/// `CreateIoCompletionPort`.  `overlapped` is stored as an opaque address.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_PostQueuedCompletionStatus(
    completion_port: *mut core::ffi::c_void,
    bytes_transferred: u32,
    completion_key: usize,
    overlapped: *mut core::ffi::c_void,
) -> i32 {
    let port_val = completion_port as usize;
    if post_iocp_completion(
        port_val,
        bytes_transferred,
        completion_key,
        overlapped as usize,
        0,
    ) {
        1 // TRUE
    } else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        0 // FALSE
    }
}

/// GetQueuedCompletionStatus - dequeues an I/O completion packet from an
/// I/O completion port.
///
/// Waits up to `milliseconds` milliseconds for a completion packet to
/// arrive on `completion_port`, then dequeues it and fills the output
/// parameters.
///
/// Returns TRUE if a packet was dequeued.  Returns FALSE with last error
/// `WAIT_TIMEOUT` (258) if the timeout expires, or `ERROR_INVALID_HANDLE`
/// (6) if the port handle is unknown.
///
/// # Panics
/// Panics if the internal IOCP mutex is poisoned.
///
/// # Safety
/// `completion_port` must be a valid IOCP handle.  All output pointer
/// arguments must be valid writable locations or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetQueuedCompletionStatus(
    completion_port: *mut core::ffi::c_void,
    bytes_transferred: *mut u32,
    completion_key: *mut usize,
    overlapped: *mut *mut core::ffi::c_void,
    milliseconds: u32,
) -> i32 {
    let port_val = completion_port as usize;

    // Retrieve the Arc holding the shared state for this port.
    let state_arc = with_iocp_handles(|map| map.get(&port_val).map(|e| Arc::clone(&e.state)));
    let Some(state_arc) = state_arc else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        if !overlapped.is_null() {
            *overlapped = core::ptr::null_mut();
        }
        return 0;
    };

    let (lock, cvar) = state_arc.as_ref();
    let mut guard = lock.lock().unwrap();

    let packet = if milliseconds == 0 {
        // Non-blocking: dequeue only if a packet is already available.
        guard.queue.pop_front()
    } else if milliseconds == u32::MAX {
        // Infinite wait.
        loop {
            if let Some(p) = guard.queue.pop_front() {
                break Some(p);
            }
            guard = cvar.wait(guard).unwrap();
        }
    } else {
        // Timed wait.
        let deadline = std::time::Instant::now() + Duration::from_millis(u64::from(milliseconds));
        loop {
            if let Some(p) = guard.queue.pop_front() {
                break Some(p);
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break None;
            }
            let (new_guard, timeout_result) = cvar.wait_timeout(guard, remaining).unwrap();
            guard = new_guard;
            if timeout_result.timed_out() {
                // One last attempt before giving up.
                if let Some(p) = guard.queue.pop_front() {
                    break Some(p);
                }
                break None;
            }
        }
    };

    if let Some(p) = packet {
        if !bytes_transferred.is_null() {
            *bytes_transferred = p.bytes_transferred;
        }
        if !completion_key.is_null() {
            *completion_key = p.completion_key;
        }
        if !overlapped.is_null() {
            *overlapped = p.overlapped as *mut core::ffi::c_void;
        }
        if p.error_code != 0 {
            kernel32_SetLastError(p.error_code);
        }
        1 // TRUE
    } else {
        kernel32_SetLastError(258); // WAIT_TIMEOUT (ERROR_TIMEOUT)
        if !overlapped.is_null() {
            *overlapped = core::ptr::null_mut();
        }
        0 // FALSE
    }
}

/// GetQueuedCompletionStatusEx - dequeues multiple I/O completion packets
/// from an I/O completion port.
///
/// Fills up to `count` entries in the `completion_port_entries` array.
/// Sets `*num_entries_removed` to the number of entries actually dequeued.
///
/// If `alertable` is non-zero, pending APC callbacks are also executed.
///
/// Returns TRUE if at least one entry was dequeued, FALSE on timeout or
/// error.
///
/// # Panics
/// Panics if the internal IOCP mutex is poisoned.
///
/// # Safety
/// `completion_port` must be a valid IOCP handle.  `completion_port_entries`
/// must point to a writable array of at least `count`
/// `OVERLAPPED_ENTRY`-like structures (32 bytes each: key usize,
/// overlapped *mut c_void, internal usize, bytes u32, for 28 bytes of
/// fields padded to 32).  `num_entries_removed` must be a valid writable
/// `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kernel32_GetQueuedCompletionStatusEx(
    completion_port: *mut core::ffi::c_void,
    completion_port_entries: *mut core::ffi::c_void,
    count: u32,
    num_entries_removed: *mut u32,
    milliseconds: u32,
    alertable: i32,
) -> i32 {
    // OVERLAPPED_ENTRY layout (Windows x64):
    // offset  0: lpCompletionKey   (usize, 8 bytes)
    // offset  8: lpOverlapped      (*mut c_void, 8 bytes)
    // offset 16: Internal          (usize, 8 bytes)  – reserved
    // offset 24: dwNumberOfBytesTransferred (u32, 4 bytes)
    // Total: 28 bytes, but typically padded to 32.
    const ENTRY_SIZE: usize = 32;

    if alertable != 0 {
        drain_apc_queue();
    }

    if completion_port_entries.is_null() || num_entries_removed.is_null() || count == 0 {
        kernel32_SetLastError(87); // ERROR_INVALID_PARAMETER
        return 0;
    }

    let port_val = completion_port as usize;
    let state_arc = with_iocp_handles(|map| map.get(&port_val).map(|e| Arc::clone(&e.state)));
    let Some(state_arc) = state_arc else {
        kernel32_SetLastError(6); // ERROR_INVALID_HANDLE
        return 0;
    };

    let (lock, cvar) = state_arc.as_ref();
    let mut guard = lock.lock().unwrap();

    // Wait for at least one packet (same logic as GetQueuedCompletionStatus).
    if guard.queue.is_empty() {
        if milliseconds == 0 {
            // No packets available and non-blocking.
            *num_entries_removed = 0;
            kernel32_SetLastError(258); // WAIT_TIMEOUT
            return 0;
        } else if milliseconds == u32::MAX {
            loop {
                if !guard.queue.is_empty() {
                    break;
                }
                guard = cvar.wait(guard).unwrap();
            }
        } else {
            let deadline =
                std::time::Instant::now() + Duration::from_millis(u64::from(milliseconds));
            loop {
                if !guard.queue.is_empty() {
                    break;
                }
                let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    *num_entries_removed = 0;
                    kernel32_SetLastError(258); // WAIT_TIMEOUT
                    return 0;
                }
                let (new_guard, timed_out) = cvar.wait_timeout(guard, remaining).unwrap();
                guard = new_guard;
                if timed_out.timed_out() && guard.queue.is_empty() {
                    *num_entries_removed = 0;
                    kernel32_SetLastError(258); // WAIT_TIMEOUT
                    return 0;
                }
            }
        }
    }

    // Drain up to `count` packets.
    let base = completion_port_entries.cast::<u8>();
    let max = (count as usize).min(guard.queue.len());
    for i in 0..max {
        let packet = guard.queue.pop_front().unwrap();
        let entry_ptr = base.add(i * ENTRY_SIZE);
        // SAFETY: caller guarantees the array is large enough.
        core::ptr::write_unaligned(entry_ptr.cast::<usize>(), packet.completion_key);
        core::ptr::write_unaligned(
            entry_ptr.add(8).cast::<*mut core::ffi::c_void>(),
            packet.overlapped as *mut core::ffi::c_void,
        );
        core::ptr::write_unaligned(entry_ptr.add(16).cast::<usize>(), 0usize); // Internal
        core::ptr::write_unaligned(entry_ptr.add(24).cast::<u32>(), packet.bytes_transferred);
    }
    *num_entries_removed = max as u32;
    1 // TRUE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep() {
        // Sleep for 10ms
        let start = std::time::Instant::now();
        unsafe { kernel32_Sleep(10) };
        let elapsed = start.elapsed();
        // Should sleep at least 10ms (allow some tolerance)
        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed < Duration::from_millis(50)); // Not too long
    }

    #[test]
    fn test_get_current_thread_id() {
        let tid = unsafe { kernel32_GetCurrentThreadId() };
        // Thread ID should be non-zero
        assert_ne!(tid, 0);
    }

    #[test]
    fn test_get_current_process_id() {
        let pid = unsafe { kernel32_GetCurrentProcessId() };
        // Process ID should be non-zero
        assert_ne!(pid, 0);
    }

    #[test]
    fn test_tls_alloc_free() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF); // Should not be TLS_OUT_OF_INDEXES

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1); // Should succeed
    }

    #[test]
    fn test_tls_get_set_value() {
        // Allocate a TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Initially should be 0
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, 0);

        // Set a value
        let test_value = 0x1234_5678_ABCD_EF00_usize;
        let result = unsafe { kernel32_TlsSetValue(slot, test_value) };
        assert_eq!(result, 1); // Should succeed

        // Get the value back
        let value = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(value, test_value);

        // Free the slot
        let result = unsafe { kernel32_TlsFree(slot) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_tls_multiple_slots() {
        // Allocate multiple slots
        let slot1 = unsafe { kernel32_TlsAlloc() };
        let slot2 = unsafe { kernel32_TlsAlloc() };
        let slot3 = unsafe { kernel32_TlsAlloc() };

        assert_ne!(slot1, 0xFFFF_FFFF);
        assert_ne!(slot2, 0xFFFF_FFFF);
        assert_ne!(slot3, 0xFFFF_FFFF);

        // Each slot should be different
        assert_ne!(slot1, slot2);
        assert_ne!(slot2, slot3);
        assert_ne!(slot1, slot3);

        // Set different values in each slot
        let value1 = 0x1111_usize;
        let value2 = 0x2222_usize;
        let value3 = 0x3333_usize;

        unsafe {
            kernel32_TlsSetValue(slot1, value1);
            kernel32_TlsSetValue(slot2, value2);
            kernel32_TlsSetValue(slot3, value3);
        }

        // Verify each slot has its own value
        assert_eq!(unsafe { kernel32_TlsGetValue(slot1) }, value1);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot2) }, value2);
        assert_eq!(unsafe { kernel32_TlsGetValue(slot3) }, value3);

        // Free all slots
        unsafe {
            kernel32_TlsFree(slot1);
            kernel32_TlsFree(slot2);
            kernel32_TlsFree(slot3);
        }
    }

    #[test]
    fn test_tls_thread_isolation() {
        use std::sync::Arc;
        use std::sync::Barrier;

        // Allocate a shared TLS slot
        let slot = unsafe { kernel32_TlsAlloc() };
        assert_ne!(slot, 0xFFFF_FFFF);

        // Use a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(3));

        let mut handles = vec![];

        for thread_num in 1..=2 {
            let barrier = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Each thread sets its own value in the same slot
                #[allow(clippy::cast_sign_loss)]
                let value = (thread_num * 1000) as usize;
                unsafe {
                    kernel32_TlsSetValue(slot, value);
                }

                // Wait for all threads to set their values
                barrier.wait();

                // Verify this thread's value hasn't been affected by other threads
                let retrieved = unsafe { kernel32_TlsGetValue(slot) };
                assert_eq!(retrieved, value);
            });
            handles.push(handle);
        }

        // Main thread also sets a value
        let main_value = 9999_usize;
        unsafe {
            kernel32_TlsSetValue(slot, main_value);
        }

        // Wait for all threads
        barrier.wait();

        // Verify main thread's value is still intact
        let retrieved = unsafe { kernel32_TlsGetValue(slot) };
        assert_eq!(retrieved, main_value);

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Free the slot
        unsafe {
            kernel32_TlsFree(slot);
        }
    }

    #[test]
    fn test_exception_handling_stubs() {
        // Test __C_specific_handler returns EXCEPTION_CONTINUE_SEARCH
        let result = unsafe {
            kernel32___C_specific_handler(
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1); // EXCEPTION_CONTINUE_SEARCH

        // Test SetUnhandledExceptionFilter returns NULL
        let prev_filter = unsafe { kernel32_SetUnhandledExceptionFilter(core::ptr::null_mut()) };
        assert!(prev_filter.is_null());

        // Test RtlCaptureContext captures real register values (non-zero for RSP/RIP at minimum)
        let mut context = vec![0u8; 1232]; // Size of Windows CONTEXT structure
        unsafe { kernel32_RtlCaptureContext(context.as_mut_ptr().cast()) };
        // RSP (offset 0x98) and RIP (offset 0xF8) should be non-zero after capture
        let rsp = u64::from_le_bytes(context[0x98..0xA0].try_into().unwrap());
        let rip = u64::from_le_bytes(context[0xF8..0x100].try_into().unwrap());
        assert_ne!(rsp, 0, "Captured RSP should be non-zero");
        assert_ne!(rip, 0, "Captured RIP should be non-zero");

        // Test RtlLookupFunctionEntry returns NULL
        let mut image_base = 0u64;
        let entry = unsafe {
            kernel32_RtlLookupFunctionEntry(
                0x1000,
                core::ptr::addr_of_mut!(image_base),
                core::ptr::null_mut(),
            )
        };
        assert!(entry.is_null());

        // Test RtlUnwindEx doesn't crash (returns nothing)
        unsafe {
            kernel32_RtlUnwindEx(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }

        // Test RtlVirtualUnwind returns NULL
        let unwind = unsafe {
            kernel32_RtlVirtualUnwind(
                0,
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(unwind.is_null());

        // Test AddVectoredExceptionHandler returns non-NULL
        let handler = unsafe { kernel32_AddVectoredExceptionHandler(1, core::ptr::null_mut()) };
        assert!(!handler.is_null());
    }

    #[test]
    fn test_seh_exception_table_registration_and_lookup() {
        // Build a minimal fake RUNTIME_FUNCTION table in memory:
        // Entry 0: functions at RVA 0x1000 – 0x1050, with fake unwind-info RVA 0x5000
        // Entry 1: functions at RVA 0x2000 – 0x2100, with fake unwind-info RVA 0x5100
        let fake_table: Vec<u32> = vec![
            0x1000, 0x1050, 0x5000, // entry 0
            0x2000, 0x2100, 0x5100, // entry 1
        ];
        let pdata_bytes = (fake_table.len() * 4) as u32;
        let pdata_raw = fake_table.as_ptr() as u64;

        // The "image_base" we tell the lookup function is the start of our fake table minus
        // the pdata_rva.  Since fake_table is at pdata_raw, and we choose pdata_rva = 0,
        // image_base = pdata_raw.
        let image_base = pdata_raw;
        let pdata_rva = 0u32;

        register_exception_table(image_base, pdata_rva, pdata_bytes);

        // Look up a PC inside entry 0
        let mut found_image_base = 0u64;
        let entry = unsafe {
            kernel32_RtlLookupFunctionEntry(
                image_base + 0x1020,
                core::ptr::addr_of_mut!(found_image_base),
                core::ptr::null_mut(),
            )
        };
        assert!(!entry.is_null(), "Should find entry 0");
        assert_eq!(
            found_image_base, image_base,
            "image_base output should match"
        );
        // Verify entry 0 fields
        let begin = unsafe { (entry as *const u32).read_unaligned() };
        let end = unsafe { (entry as *const u32).add(1).read_unaligned() };
        assert_eq!(begin, 0x1000);
        assert_eq!(end, 0x1050);

        // Look up a PC inside entry 1
        let entry2 = unsafe {
            kernel32_RtlLookupFunctionEntry(
                image_base + 0x20FF,
                core::ptr::addr_of_mut!(found_image_base),
                core::ptr::null_mut(),
            )
        };
        assert!(!entry2.is_null(), "Should find entry 1");
        let begin2 = unsafe { (entry2 as *const u32).read_unaligned() };
        assert_eq!(begin2, 0x2000);

        // A PC outside all ranges should return NULL
        let miss = unsafe {
            kernel32_RtlLookupFunctionEntry(
                image_base + 0x9999,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert!(miss.is_null(), "Out-of-range PC should return NULL");

        // Clear the global exception table to prevent a dangling pointer:
        // fake_table is stack-allocated and will be dropped at end of scope.
        // Any subsequent test that calls RtlLookupFunctionEntry would otherwise
        // read freed memory via the stored pointer.
        {
            let mut guard = EXCEPTION_TABLE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *guard = None;
        }
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_seh_virtual_unwind_basic() {
        const RETURN_ADDR: u64 = 0xDEAD_BEEF_1234_5678;

        // Build a minimal PE in memory:
        //
        //  image_base (fake):  start of image_mem
        //  Function at RVA 0x1000, size 0x100
        //
        // UNWIND_INFO at RVA 0x5000:
        //   Byte 0: 0x01  (Version=1, Flags=0)
        //   Byte 1: 0x08  (SizeOfProlog = 8)
        //   Byte 2: 0x01  (CountOfCodes = 1)
        //   Byte 3: 0x00  (FrameRegister=0, FrameOffset=0)
        //   UNWIND_CODE[0]: UWOP_ALLOC_SMALL with op_info=3
        //     → (3+1)*8 = 32 bytes sub rsp in prolog
        //     → unwind effect: RSP += 32

        let image_size = 0x6000usize;
        let mut image_mem = vec![0u8; image_size];

        // Write RUNTIME_FUNCTION at offset 0 (used as pdata)
        let rf_ptr = image_mem.as_mut_ptr().cast::<u32>();
        unsafe {
            rf_ptr.write_unaligned(0x1000); // BeginAddress
            rf_ptr.add(1).write_unaligned(0x1100); // EndAddress
            rf_ptr.add(2).write_unaligned(0x5000); // UnwindInfoAddress
        }

        // Write UNWIND_INFO at offset 0x5000
        let ui_ptr = unsafe { image_mem.as_mut_ptr().add(0x5000) };
        // UWOP_ALLOC_SMALL: code_offset=8, op=2, op_info=3
        let alloc_small_code: u16 = 0x08 | (2u16 << 8) | (3u16 << 12);
        unsafe {
            ui_ptr.write(0x01); // Version=1, Flags=0
            ui_ptr.add(1).write(0x08); // SizeOfProlog=8
            ui_ptr.add(2).write(0x01); // CountOfCodes=1
            ui_ptr.add(3).write(0x00); // FrameRegister=0, FrameOffset=0
            ui_ptr
                .add(4)
                .cast::<u16>()
                .write_unaligned(alloc_small_code);
        }

        // All writes are done; obtain the image base for use in RtlVirtualUnwind.
        let image_base = image_mem.as_ptr() as u64;

        // Build a fake stack.  The prolog executed "sub rsp, 32", so at the time
        // the context is captured (after prolog), RSP is 32 bytes below where it
        // was before the call.  The stack layout (low→high) is:
        //
        //   [fake_rsp+0 .. +31]  : local frame / shadow space (4 × u64 = 32 bytes)
        //   [fake_rsp+32]        : return address = 0xDEAD_BEEF_1234_5678
        //
        // After ALLOC_SMALL unwind: RSP += 32 → points at return address
        // After pop return address: RSP += 8  → fake_rsp + 40
        // 5 slots: 4 × local + 1 × return address
        let fake_stack: Vec<u64> = vec![0u64, 0u64, 0u64, 0u64, RETURN_ADDR];
        let fake_rsp = fake_stack.as_ptr() as u64;

        // Set up CONTEXT with RSP = fake_rsp
        let mut ctx = vec![0u8; 1232usize];
        ctx[0x98..0xA0].copy_from_slice(&fake_rsp.to_le_bytes());

        let function_entry = image_mem.as_mut_ptr().cast::<core::ffi::c_void>();
        let mut handler_data: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut establisher_frame = 0u64;

        // control_pc is past the prolog (offset 0x1080 >> SizeOfProlog 0x08)
        let control_pc = image_base + 0x1080;
        let handler = unsafe {
            kernel32_RtlVirtualUnwind(
                0,
                image_base,
                control_pc,
                function_entry,
                ctx.as_mut_ptr().cast(),
                core::ptr::addr_of_mut!(handler_data),
                core::ptr::addr_of_mut!(establisher_frame),
                core::ptr::null_mut(),
            )
        };

        // Flags=0 → no handler
        assert!(handler.is_null(), "No handler expected");

        // After ALLOC_SMALL(3): RSP += 32, then pop return address: RSP += 8
        let final_rsp = u64::from_le_bytes(ctx[0x98..0xA0].try_into().unwrap());
        assert_eq!(
            final_rsp,
            fake_rsp + 40,
            "RSP should advance by alloc (32) + return pop (8)"
        );

        // RIP = return address
        let final_rip = u64::from_le_bytes(ctx[0xF8..0x100].try_into().unwrap());
        assert_eq!(final_rip, RETURN_ADDR, "RIP should be the return address");

        // Establisher frame = RSP before popping the return address
        assert_eq!(
            establisher_frame,
            fake_rsp + 32,
            "Establisher frame = RSP after alloc unwind, before return pop"
        );
    }

    #[test]
    fn test_critical_section_basic() {
        // Allocate a critical section
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };
        assert_ne!(cs.internal, 0); // Should be initialized

        // Enter the critical section
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the critical section
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Delete the critical section
        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
        assert_eq!(cs.internal, 0); // Should be cleared
    }

    #[test]
    fn test_critical_section_recursion() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Enter multiple times (recursion)
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };

        // Leave the same number of times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        // Should be able to enter again after leaving all
        unsafe { kernel32_EnterCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_try_enter() {
        let mut cs = CriticalSection {
            internal: 0,
            _padding: [0; 32],
        };

        unsafe { kernel32_InitializeCriticalSection(&raw mut cs) };

        // Try to enter - should succeed when not held
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Try to enter again (same thread) - should succeed (recursion)
        let result = unsafe { kernel32_TryEnterCriticalSection(&raw mut cs) };
        assert_eq!(result, 1); // Success

        // Leave both times
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };
        unsafe { kernel32_LeaveCriticalSection(&raw mut cs) };

        unsafe { kernel32_DeleteCriticalSection(&raw mut cs) };
    }

    #[test]
    fn test_critical_section_multi_thread() {
        use std::sync::Arc;
        use std::thread;

        // Allocate a critical section in shared memory
        let cs = Arc::new(std::sync::Mutex::new(CriticalSection {
            internal: 0,
            _padding: [0; 32],
        }));

        // Initialize it
        unsafe { kernel32_InitializeCriticalSection(&raw mut *cs.lock().unwrap()) };

        // Shared counter
        let counter = Arc::new(std::sync::Mutex::new(0));

        // Spawn multiple threads
        let handles: Vec<_> = (0..5)
            .map(|_| {
                let cs = Arc::clone(&cs);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    for _ in 0..100 {
                        // Enter critical section
                        unsafe { kernel32_EnterCriticalSection(&raw mut *cs.lock().unwrap()) };

                        // Increment counter (protected by critical section)
                        let mut c = counter.lock().unwrap();
                        *c += 1;
                        drop(c);

                        // Leave critical section
                        unsafe { kernel32_LeaveCriticalSection(&raw mut *cs.lock().unwrap()) };
                    }
                })
            })
            .collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Check that all increments happened
        assert_eq!(*counter.lock().unwrap(), 500);

        // Clean up
        unsafe { kernel32_DeleteCriticalSection(&raw mut *cs.lock().unwrap()) };
    }

    #[test]
    fn test_critical_section_null_safe() {
        // All functions should handle NULL gracefully
        unsafe { kernel32_InitializeCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_EnterCriticalSection(core::ptr::null_mut()) };
        unsafe { kernel32_LeaveCriticalSection(core::ptr::null_mut()) };
        let result = unsafe { kernel32_TryEnterCriticalSection(core::ptr::null_mut()) };
        assert_eq!(result, 0); // Should return false for NULL
        unsafe { kernel32_DeleteCriticalSection(core::ptr::null_mut()) };
    }

    //
    // Phase 8.3: String Operations Tests
    //

    #[test]
    fn test_multibyte_to_wide_char_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = b"Hello";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (5 chars, no null terminator when length is explicit)
        assert_eq!(result, 5);
        // Verify the conversion
        assert_eq!(output[0], u16::from(b'H'));
        assert_eq!(output[1], u16::from(b'e'));
        assert_eq!(output[2], u16::from(b'l'));
        assert_eq!(output[3], u16::from(b'l'));
        assert_eq!(output[4], u16::from(b'o'));
    }

    #[test]
    fn test_multibyte_to_wide_char_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = b"Hello World";

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
            )
        };

        // Should return 11 (11 chars, no null terminator when length is explicit)
        assert_eq!(result, 11);
    }

    #[test]
    fn test_multibyte_to_wide_char_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = b"Test\0";
        let mut output = [0u16; 10];

        let result = unsafe {
            kernel32_MultiByteToWideChar(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
            )
        };

        // Should return 5 (4 chars + null terminator)
        assert_eq!(result, 5);
        assert_eq!(output[0], u16::from(b'T'));
        assert_eq!(output[3], u16::from(b't'));
        assert_eq!(output[4], 0);
    }

    #[test]
    fn test_wide_char_to_multibyte_basic() {
        // Test basic ASCII conversion with explicit length (no null terminator)
        let input = [u16::from(b'H'), u16::from(b'i'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                2, // Length without null
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 2 (2 chars, no null terminator when length is explicit)
        assert_eq!(result, 2);
        assert_eq!(output[0], b'H');
        assert_eq!(output[1], b'i');
    }

    #[test]
    fn test_wide_char_to_multibyte_query_size() {
        // Test querying required buffer size (explicit length, no null)
        let input = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            u16::from(b' '),
            u16::from(b'!'),
        ];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                input.len() as i32,
                core::ptr::null_mut(),
                0,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 6 (6 chars, no null terminator when length is explicit)
        assert_eq!(result, 6);
    }

    #[test]
    fn test_wide_char_to_multibyte_null_terminated() {
        // Test with null-terminated string (-1 length)
        let input = [u16::from(b'A'), u16::from(b'B'), u16::from(b'C'), 0];
        let mut output = [0u8; 10];

        let result = unsafe {
            kernel32_WideCharToMultiByte(
                65001, // CP_UTF8
                0,
                input.as_ptr(),
                -1, // Null-terminated
                output.as_mut_ptr(),
                output.len() as i32,
                core::ptr::null(),
                core::ptr::null_mut(),
            )
        };

        // Should return 4 (3 chars + null terminator)
        assert_eq!(result, 4);
        assert_eq!(output[0], b'A');
        assert_eq!(output[1], b'B');
        assert_eq!(output[2], b'C');
        assert_eq!(output[3], 0);
    }

    #[test]
    fn test_lstrlenw_basic() {
        // Test basic wide string length
        let input = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 5);
    }

    #[test]
    fn test_lstrlenw_empty() {
        // Test empty string
        let input = [0u16];

        let result = unsafe { kernel32_lstrlenW(input.as_ptr()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_lstrlenw_null() {
        // Test NULL pointer
        let result = unsafe { kernel32_lstrlenW(core::ptr::null()) };

        assert_eq!(result, 0);
    }

    #[test]
    fn test_compare_string_ordinal_equal() {
        // Test equal strings
        let str1 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];
        let str2 = [
            u16::from(b'T'),
            u16::from(b'e'),
            u16::from(b's'),
            u16::from(b't'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                4,
                str2.as_ptr(),
                4,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    #[test]
    fn test_compare_string_ordinal_less_than() {
        // Test str1 < str2
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'C'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 1); // CSTR_LESS_THAN
    }

    #[test]
    fn test_compare_string_ordinal_greater_than() {
        // Test str1 > str2
        let str1 = [u16::from(b'Z'), u16::from(b'Z'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'A'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                2,
                str2.as_ptr(),
                2,
                0, // Case-sensitive
            )
        };

        assert_eq!(result, 3); // CSTR_GREATER_THAN
    }

    #[test]
    fn test_compare_string_ordinal_ignore_case() {
        // Test case-insensitive comparison
        let str1 = [
            u16::from(b'H'),
            u16::from(b'e'),
            u16::from(b'l'),
            u16::from(b'l'),
            u16::from(b'o'),
            0,
        ];
        let str2 = [
            u16::from(b'h'),
            u16::from(b'E'),
            u16::from(b'L'),
            u16::from(b'L'),
            u16::from(b'O'),
            0,
        ];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                5,
                str2.as_ptr(),
                5,
                1, // Ignore case
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL (case-insensitive)
    }

    #[test]
    fn test_compare_string_ordinal_null_terminated() {
        // Test with -1 (null-terminated strings)
        let str1 = [u16::from(b'A'), u16::from(b'B'), 0];
        let str2 = [u16::from(b'A'), u16::from(b'B'), 0];

        let result = unsafe {
            kernel32_CompareStringOrdinal(
                str1.as_ptr(),
                -1, // Null-terminated
                str2.as_ptr(),
                -1, // Null-terminated
                0,  // Case-sensitive
            )
        };

        assert_eq!(result, 2); // CSTR_EQUAL
    }

    //
    // Phase 8.4: Performance Counters Tests
    //

    #[test]
    fn test_query_performance_counter() {
        let mut counter: i64 = 0;

        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter)) };

        assert_eq!(result, 1); // TRUE - success
        assert!(counter > 0); // Should be positive
    }

    #[test]
    fn test_query_performance_counter_monotonic() {
        let mut counter1: i64 = 0;
        let mut counter2: i64 = 0;

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter1)) };

        // Do some work
        for _ in 0..1000 {
            core::hint::black_box(42);
        }

        unsafe { kernel32_QueryPerformanceCounter(core::ptr::addr_of_mut!(counter2)) };

        // counter2 should be >= counter1 (monotonic)
        assert!(counter2 >= counter1);
    }

    #[test]
    fn test_query_performance_counter_null() {
        let result = unsafe { kernel32_QueryPerformanceCounter(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_query_performance_frequency() {
        let mut frequency: i64 = 0;

        let result =
            unsafe { kernel32_QueryPerformanceFrequency(core::ptr::addr_of_mut!(frequency)) };

        assert_eq!(result, 1); // TRUE - success
        assert_eq!(frequency, 1_000_000_000); // 1 billion (nanoseconds)
    }

    #[test]
    fn test_query_performance_frequency_null() {
        let result = unsafe { kernel32_QueryPerformanceFrequency(core::ptr::null_mut()) };

        assert_eq!(result, 0); // FALSE - error
    }

    #[test]
    fn test_get_system_time_precise_as_filetime() {
        let mut filetime = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime)) };

        // Should have non-zero values (representing time since 1601)
        assert!(filetime.high_date_time > 0);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_increases() {
        let mut filetime1 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut filetime2 = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime1)) };

        // Sleep a tiny bit
        thread::sleep(Duration::from_millis(1));

        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::addr_of_mut!(filetime2)) };

        // Reconstruct the 64-bit values
        let time1 =
            u64::from(filetime1.low_date_time) | (u64::from(filetime1.high_date_time) << 32);
        let time2 =
            u64::from(filetime2.low_date_time) | (u64::from(filetime2.high_date_time) << 32);

        // time2 should be > time1
        assert!(time2 > time1);
    }

    #[test]
    fn test_get_system_time_precise_as_filetime_null() {
        // Should not crash with NULL
        unsafe { kernel32_GetSystemTimePreciseAsFileTime(core::ptr::null_mut()) };
    }

    //
    // Phase 8.5: File I/O Trampolines Tests
    //

    #[test]
    fn test_create_file_w_returns_invalid_handle() {
        // CreateFileW should return INVALID_HANDLE_VALUE
        let handle = unsafe {
            kernel32_CreateFileW(
                core::ptr::null(),
                0,
                0,
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
            )
        };

        // INVALID_HANDLE_VALUE is usize::MAX
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_read_file_returns_false() {
        // ReadFile should return FALSE (0)
        let result = unsafe {
            kernel32_ReadFile(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_write_file_returns_false() {
        // WriteFile should return FALSE (0)
        let result = unsafe {
            kernel32_WriteFile(
                core::ptr::null_mut(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0); // FALSE
    }

    #[test]
    fn test_close_handle_returns_true() {
        // CloseHandle should return TRUE (1)
        let result = unsafe { kernel32_CloseHandle(core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    //
    // Phase 8.6: Heap Management Trampolines Tests
    //

    #[test]
    fn test_get_process_heap() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Should return non-NULL
        assert!(!heap.is_null());
    }

    #[test]
    fn test_heap_alloc_basic() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 1024;

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Clean up (even though our implementation leaks)
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 256;

        let ptr = unsafe { kernel32_HeapAlloc(heap, HEAP_ZERO_MEMORY, size) };

        // Should allocate successfully
        assert!(!ptr.is_null());

        // Verify memory is zeroed
        let slice = unsafe { core::slice::from_raw_parts(ptr.cast::<u8>(), size) };
        assert!(slice.iter().all(|&b| b == 0));

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_alloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 0) };

        // Windows HeapAlloc returns a non-NULL pointer for 0-byte allocation
        // We allocate a minimal block (1 byte) to match Windows semantics
        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_free_null() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Freeing NULL should succeed
        let result = unsafe { kernel32_HeapFree(heap, 0, core::ptr::null_mut()) };

        assert_eq!(result, 1); // TRUE
    }

    #[test]
    fn test_heap_realloc_null_to_alloc() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // ReAlloc with NULL pointer should allocate new memory
        let ptr = unsafe { kernel32_HeapReAlloc(heap, 0, core::ptr::null_mut(), 512) };

        assert!(!ptr.is_null());

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_size() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };

        // ReAlloc to zero size should free memory
        let result = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, 0) };

        assert!(result.is_null());
    }

    #[test]
    fn test_heap_alloc_free_cycle() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let size = 512;

        // Allocate memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, size) };
        assert!(!ptr.is_null());

        // Write some data to verify it's writable
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), size);
            slice.fill(0xAB);
        }

        // Free it
        let result = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result, 1); // TRUE - success
    }

    #[test]
    fn test_heap_realloc_grow() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to larger size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify original data is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), initial_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_shrink() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 1024;
        let new_size = 256;

        // Allocate initial memory
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill with test data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), new_size);
            for (i, byte) in slice.iter_mut().enumerate() {
                *byte = (i % 256) as u8;
            }
        }

        // Reallocate to smaller size
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, 0, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify data in the remaining portion is preserved
        unsafe {
            let slice = core::slice::from_raw_parts(new_ptr.cast::<u8>(), new_size);
            for (i, &byte) in slice.iter().enumerate() {
                assert_eq!(byte, (i % 256) as u8, "Data corruption at offset {i}");
            }
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_realloc_zero_new_memory() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let initial_size = 256;
        let new_size = 1024;

        // Allocate and reallocate with HEAP_ZERO_MEMORY flag
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, initial_size) };
        assert!(!ptr.is_null());

        // Fill initial allocation with non-zero data
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr.cast::<u8>(), initial_size);
            slice.fill(0xFF);
        }

        // Reallocate to larger size with zero flag
        let new_ptr = unsafe { kernel32_HeapReAlloc(heap, HEAP_ZERO_MEMORY, ptr, new_size) };
        assert!(!new_ptr.is_null());

        // Verify that the new portion (beyond initial_size) is zeroed
        unsafe {
            let slice = core::slice::from_raw_parts(
                new_ptr.cast::<u8>().add(initial_size),
                new_size - initial_size,
            );
            assert!(slice.iter().all(|&b| b == 0), "New memory not zeroed");
        }

        // Clean up
        unsafe { kernel32_HeapFree(heap, 0, new_ptr) };
    }

    #[test]
    fn test_heap_free_double_free_protection() {
        let heap = unsafe { kernel32_GetProcessHeap() };
        let ptr = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        assert!(!ptr.is_null());

        // First free should succeed
        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result1, 1); // TRUE

        // Second free should fail (allocation not found)
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr) };
        assert_eq!(result2, 0); // FALSE
    }

    #[test]
    fn test_heap_multiple_allocations() {
        let heap = unsafe { kernel32_GetProcessHeap() };

        // Allocate multiple blocks
        let ptr1 = unsafe { kernel32_HeapAlloc(heap, 0, 128) };
        let ptr2 = unsafe { kernel32_HeapAlloc(heap, 0, 256) };
        let ptr3 = unsafe { kernel32_HeapAlloc(heap, 0, 512) };

        assert!(!ptr1.is_null());
        assert!(!ptr2.is_null());
        assert!(!ptr3.is_null());

        // All pointers should be different
        assert_ne!(ptr1, ptr2);
        assert_ne!(ptr2, ptr3);
        assert_ne!(ptr1, ptr3);

        // Free in different order
        let result2 = unsafe { kernel32_HeapFree(heap, 0, ptr2) };
        assert_eq!(result2, 1);

        let result1 = unsafe { kernel32_HeapFree(heap, 0, ptr1) };
        assert_eq!(result1, 1);

        let result3 = unsafe { kernel32_HeapFree(heap, 0, ptr3) };
        assert_eq!(result3, 1);
    }

    #[test]
    fn test_get_set_last_error() {
        // Initially, last error should be 0
        let initial_error = unsafe { kernel32_GetLastError() };
        assert_eq!(initial_error, 0, "Initial error should be 0");

        // Set an error code
        unsafe { kernel32_SetLastError(5) }; // ERROR_ACCESS_DENIED

        // Get the error back
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 5, "GetLastError should return the set error code");

        // Set a different error
        unsafe { kernel32_SetLastError(2) }; // ERROR_FILE_NOT_FOUND

        let error2 = unsafe { kernel32_GetLastError() };
        assert_eq!(error2, 2, "GetLastError should return the new error code");

        // Reset to 0
        unsafe { kernel32_SetLastError(0) };
        let error3 = unsafe { kernel32_GetLastError() };
        assert_eq!(error3, 0, "Error should be reset to 0");
    }

    #[test]
    fn test_last_error_thread_isolation() {
        use std::sync::{Arc, Barrier};

        // Create a barrier to synchronize threads
        let barrier = Arc::new(Barrier::new(2));
        let barrier_clone = barrier.clone();

        // Set error in main thread
        unsafe { kernel32_SetLastError(100) };

        // Spawn a thread that sets a different error
        let handle = std::thread::spawn(move || {
            // Set error in spawned thread
            unsafe { kernel32_SetLastError(200) };

            // Wait for main thread
            barrier_clone.wait();

            // Check that spawned thread's error is isolated
            let error = unsafe { kernel32_GetLastError() };
            assert_eq!(error, 200, "Spawned thread should have its own error");
        });

        // Wait for spawned thread
        barrier.wait();

        // Check that main thread's error is still 100
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 100, "Main thread error should be isolated");

        // Wait for thread to finish
        handle.join().unwrap();
    }

    #[test]
    fn test_get_current_directory() {
        // Get current directory
        let buffer_size = 1024u32;
        let mut buffer = vec![0u16; buffer_size as usize];

        let result = unsafe { kernel32_GetCurrentDirectoryW(buffer_size, buffer.as_mut_ptr()) };
        assert!(result > 0, "GetCurrentDirectoryW should succeed");
        assert!(result < buffer_size, "Result should fit in buffer");

        // Convert to string and verify it's a valid path
        let dir_str = String::from_utf16_lossy(&buffer[..result as usize]);
        assert!(!dir_str.is_empty(), "Directory should not be empty");
    }

    #[test]
    fn test_set_current_directory() {
        // Use CwdGuard for a safe, panic-proof restore of the original directory.
        let _guard = CwdGuard::new();

        // Try to set to /tmp (which should exist on Linux)
        let tmp_path: Vec<u16> = "/tmp\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(tmp_path.as_ptr()) };
        assert_eq!(result, 1, "SetCurrentDirectoryW to /tmp should succeed");

        // Verify it changed
        let buffer_size = 1024u32;
        let mut new_buffer = vec![0u16; buffer_size as usize];
        let new_len =
            unsafe { kernel32_GetCurrentDirectoryW(buffer_size, new_buffer.as_mut_ptr()) };
        assert!(new_len > 0);
        let new_dir = String::from_utf16_lossy(&new_buffer[..new_len as usize]);
        assert!(
            new_dir.contains("tmp"),
            "Current directory should now be /tmp"
        );
        // CwdGuard restores the original directory when it drops at end of test.
    }

    #[test]
    fn test_set_current_directory_invalid() {
        // Try to set to a non-existent directory
        let invalid_path: Vec<u16> = "/nonexistent_dir_12345\0".encode_utf16().collect();
        let result = unsafe { kernel32_SetCurrentDirectoryW(invalid_path.as_ptr()) };
        assert_eq!(
            result, 0,
            "SetCurrentDirectoryW should fail for invalid path"
        );

        // Check that last error was set
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 2, "Last error should be ERROR_FILE_NOT_FOUND");
    }

    #[test]
    fn test_write_file_stdout() {
        // Get stdout handle
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        assert!(!stdout.is_null());

        // Write some data
        let data = b"test output";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 1, "WriteFile should succeed for stdout");
        assert_eq!(bytes_written, data.len() as u32, "Should write all bytes");
    }

    #[test]
    fn test_write_file_invalid_handle() {
        // Try to write to invalid handle
        let invalid_handle = 0x9999 as *mut core::ffi::c_void;
        let data = b"test";
        let mut bytes_written = 0u32;
        let result = unsafe {
            kernel32_WriteFile(
                invalid_handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for invalid handle");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 6, "Should set ERROR_INVALID_HANDLE");
    }

    #[test]
    fn test_write_file_null_buffer() {
        let stdout = unsafe { kernel32_GetStdHandle((-11i32) as u32) };
        let mut bytes_written = 0xFFFF_FFFFu32; // Set to non-zero to verify it gets cleared

        let result = unsafe {
            kernel32_WriteFile(
                stdout,
                core::ptr::null(),
                10,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        assert_eq!(result, 0, "WriteFile should fail for null buffer");
        assert_eq!(bytes_written, 0, "bytes_written should be set to 0");
        let error = unsafe { kernel32_GetLastError() };
        assert_eq!(error, 87, "Should set ERROR_INVALID_PARAMETER");
    }

    #[test]
    fn test_get_command_line_w() {
        let cmd_line = unsafe { kernel32_GetCommandLineW() };
        assert!(
            !cmd_line.is_null(),
            "GetCommandLineW should not return null"
        );

        // Should be null-terminated
        let first_char = unsafe { *cmd_line };
        assert_eq!(
            first_char, 0,
            "Empty command line should have null terminator"
        );
    }

    #[test]
    fn test_get_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        assert!(
            !env.is_null(),
            "GetEnvironmentStringsW should not return null"
        );

        // The block is now real: scan for the double-null terminator.
        // It must end with \0\0 (empty-string entry = end of block).
        let mut i = 0usize;
        loop {
            let c0 = unsafe { *env.add(i) };
            let c1 = unsafe { *env.add(i + 1) };
            if c0 == 0 && c1 == 0 {
                break; // found double-null terminator
            }
            i += 1;
            assert!(
                i < 65_536,
                "environment block has no double-null terminator"
            );
        }
    }

    #[test]
    fn test_free_environment_strings_w() {
        let env = unsafe { kernel32_GetEnvironmentStringsW() };
        let result = unsafe { kernel32_FreeEnvironmentStringsW(env) };
        assert_eq!(result, 1, "FreeEnvironmentStringsW should return TRUE");
    }

    #[test]
    fn test_get_current_process() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        assert!(
            !handle.is_null(),
            "GetCurrentProcess should return non-null"
        );
        // Windows pseudo-handle for current process is -1
        assert_eq!(handle as usize, usize::MAX);
    }

    #[test]
    fn test_get_current_thread() {
        let handle = unsafe { kernel32_GetCurrentThread() };
        assert!(!handle.is_null(), "GetCurrentThread should return non-null");
        // Windows pseudo-handle for current thread is -2
        assert_eq!(handle as usize, usize::MAX - 1);
    }

    #[test]
    fn test_get_module_handle_a() {
        let handle = unsafe { kernel32_GetModuleHandleA(core::ptr::null()) };
        assert!(
            !handle.is_null(),
            "GetModuleHandleA(NULL) should return non-null"
        );
        assert_eq!(handle as usize, 0x400000);
    }

    #[test]
    fn test_get_system_info() {
        let mut info = [0u8; 48]; // SystemInfo is 48 bytes
        unsafe { kernel32_GetSystemInfo(info.as_mut_ptr()) };

        // Verify page size (offset 0x04, u32)
        let page_size = u32::from_le_bytes(info[4..8].try_into().unwrap());
        assert_eq!(page_size, 4096, "Page size should be 4096");

        // Verify number of processors (offset 0x20, u32)
        let num_processors = u32::from_le_bytes(info[0x20..0x24].try_into().unwrap());
        assert!(num_processors >= 1, "Should have at least 1 processor");
    }

    #[test]
    fn test_get_console_mode() {
        let mut mode: u32 = 0;
        let result = unsafe { kernel32_GetConsoleMode(std::ptr::dangling_mut(), &raw mut mode) };
        assert_eq!(result, 1, "GetConsoleMode should return TRUE");
        assert_ne!(mode, 0, "Mode should be non-zero");
    }

    #[test]
    fn test_get_console_output_cp() {
        let cp = unsafe { kernel32_GetConsoleOutputCP() };
        assert_eq!(cp, 65001, "Console output code page should be UTF-8");
    }

    #[test]
    fn test_virtual_protect() {
        let mut old_protect: u32 = 0;
        let result = unsafe {
            kernel32_VirtualProtect(
                0x1000 as *mut core::ffi::c_void,
                4096,
                0x04, // PAGE_READWRITE
                &raw mut old_protect,
            )
        };
        assert_eq!(result, 1, "VirtualProtect should return TRUE");
        assert_eq!(
            old_protect, 0x40,
            "Old protect should be PAGE_EXECUTE_READWRITE"
        );
    }

    #[test]
    fn test_free_library() {
        let result = unsafe { kernel32_FreeLibrary(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FreeLibrary should return TRUE");
    }

    #[test]
    fn test_find_close() {
        let result = unsafe { kernel32_FindClose(0x1000 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "FindClose should return TRUE");
    }

    #[test]
    fn test_get_environment_variable_w() {
        // When querying with null buffer / size 0, the function should return the
        // required buffer size (> 0) if PATH is set, or 0 if PATH is not in the
        // environment.  Either way it must not crash.
        let name: [u16; 5] = [
            u16::from(b'P'),
            u16::from(b'A'),
            u16::from(b'T'),
            u16::from(b'H'),
            0,
        ];
        let result =
            unsafe { kernel32_GetEnvironmentVariableW(name.as_ptr(), core::ptr::null_mut(), 0) };
        // PATH is typically set in any CI environment, so result > 0 (required size).
        // The key assertion is that the call doesn't crash/panic.
        let _ = result; // just verify no crash
    }

    #[test]
    fn test_set_environment_variable_w() {
        let name: [u16; 2] = [u16::from(b'X'), 0];
        let value: [u16; 2] = [u16::from(b'Y'), 0];
        let result = unsafe { kernel32_SetEnvironmentVariableW(name.as_ptr(), value.as_ptr()) };
        assert_eq!(result, 1, "SetEnvironmentVariableW should return TRUE");
    }

    #[test]
    fn test_get_acp() {
        let result = unsafe { kernel32_GetACP() };
        assert_eq!(result, 65001); // UTF-8
    }

    #[test]
    fn test_is_processor_feature_present() {
        unsafe {
            assert_eq!(kernel32_IsProcessorFeaturePresent(10), 1); // SSE2
            assert_eq!(kernel32_IsProcessorFeaturePresent(12), 1); // NX
            assert_eq!(kernel32_IsProcessorFeaturePresent(23), 1); // FastFail
            assert_eq!(kernel32_IsProcessorFeaturePresent(99), 0); // Unknown
        }
    }

    #[test]
    fn test_is_debugger_present() {
        let result = unsafe { kernel32_IsDebuggerPresent() };
        assert_eq!(result, 0);
    }

    #[test]
    fn test_fls_operations() {
        unsafe {
            let index = kernel32_FlsAlloc(core::ptr::null_mut());
            assert_ne!(index, 0xFFFFFFFF); // TLS_OUT_OF_INDEXES

            let set_result = kernel32_FlsSetValue(index, 0x42);
            assert_eq!(set_result, 1); // TRUE

            let value = kernel32_FlsGetValue(index);
            assert_eq!(value, 0x42);

            let free_result = kernel32_FlsFree(index);
            assert_eq!(free_result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_oem_cp() {
        let result = unsafe { kernel32_GetOEMCP() };
        assert_eq!(result, 437);
    }

    #[test]
    fn test_is_valid_code_page() {
        unsafe {
            assert_eq!(kernel32_IsValidCodePage(65001), 1); // UTF-8
            assert_eq!(kernel32_IsValidCodePage(1252), 1); // Windows-1252
            assert_eq!(kernel32_IsValidCodePage(99999), 0); // Invalid
        }
    }

    #[test]
    fn test_get_cp_info() {
        unsafe {
            let mut cp_info = [0u8; 18];
            let result = kernel32_GetCPInfo(65001, cp_info.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // First 4 bytes are MaxCharSize (should be 4 for UTF-8)
            let max_char_size =
                u32::from_le_bytes([cp_info[0], cp_info[1], cp_info[2], cp_info[3]]);
            assert_eq!(max_char_size, 4);
            // DefaultChar should be '?'
            assert_eq!(cp_info[4], 0x3F);
        }
    }

    #[test]
    fn test_decode_encode_pointer() {
        unsafe {
            let original = 0x12345678usize as *mut core::ffi::c_void;
            let encoded = kernel32_EncodePointer(original);
            let decoded = kernel32_DecodePointer(encoded);
            assert_eq!(decoded, original);
        }
    }

    #[test]
    fn test_get_tick_count_64() {
        unsafe {
            let tick1 = kernel32_GetTickCount64();
            assert!(tick1 > 0);
            std::thread::sleep(std::time::Duration::from_millis(10));
            let tick2 = kernel32_GetTickCount64();
            assert!(tick2 >= tick1);
        }
    }

    #[test]
    fn test_virtual_alloc_free() {
        unsafe {
            let ptr = kernel32_VirtualAlloc(
                core::ptr::null_mut(),
                4096,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            );
            assert!(!ptr.is_null());

            // Write to the allocated memory to verify it's usable
            *ptr.cast::<u8>() = 42;
            assert_eq!(*(ptr as *const u8), 42);

            // Per Windows API contract, MEM_RELEASE uses dwSize = 0;
            // our tracker should supply the original allocation size.
            let result = kernel32_VirtualFree(ptr, 0, 0x8000); // MEM_RELEASE
            assert_eq!(result, 1); // TRUE
        }
    }

    #[test]
    fn test_get_string_type_w() {
        unsafe {
            let input: [u16; 4] = [u16::from(b'A'), u16::from(b'1'), u16::from(b' '), 0];
            let mut output = [0u16; 3];
            let result = kernel32_GetStringTypeW(1, input.as_ptr(), 3, output.as_mut_ptr());
            assert_eq!(result, 1); // TRUE
            // 'A' should have C1_ALPHA | C1_UPPER
            assert_ne!(output[0] & 0x100, 0); // C1_ALPHA
            assert_ne!(output[0] & 0x001, 0); // C1_UPPER
            // '1' should have C1_DIGIT
            assert_ne!(output[1] & 0x004, 0); // C1_DIGIT
            // ' ' should have C1_SPACE
            assert_ne!(output[2] & 0x008, 0); // C1_SPACE
        }
    }

    #[test]
    fn test_initialize_critical_section_and_spin_count() {
        unsafe {
            let mut cs = core::mem::zeroed::<CriticalSection>();
            let result = kernel32_InitializeCriticalSectionAndSpinCount(&raw mut cs, 4000);
            assert_eq!(result, 1); // TRUE
            kernel32_DeleteCriticalSection(&raw mut cs);
        }
    }

    #[test]
    fn test_file_create_write_read_close_roundtrip() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        // Use a unique temp path to avoid conflicts with parallel test runs
        let path = "/tmp/litebox_kernel32_roundtrip_test.txt";
        let _ = std::fs::remove_file(path);

        // Encode path as UTF-16
        let wide_path: Vec<u16> = OsStr::new(path)
            .as_bytes()
            .iter()
            .map(|&b| u16::from(b))
            .chain(std::iter::once(0u16))
            .collect();

        unsafe {
            // CreateFileW — CREATE_ALWAYS | GENERIC_WRITE
            let handle = kernel32_CreateFileW(
                wide_path.as_ptr(),
                0x4000_0000, // GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX, "CreateFileW (write) failed");

            let data = b"Hello, LiteBox!";
            let mut written: u32 = 0;
            let ok = kernel32_WriteFile(
                handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut written,
                core::ptr::null_mut(),
            );
            assert_eq!(ok, 1, "WriteFile failed");
            assert_eq!(written as usize, data.len());

            // GetFileSizeEx
            let mut file_size: i64 = -1;
            let ok = kernel32_GetFileSizeEx(handle, &raw mut file_size);
            assert_eq!(ok, 1, "GetFileSizeEx failed");
            assert_eq!(file_size, data.len() as i64);

            // SetFilePointerEx — seek to start (FILE_BEGIN = 0)
            let ok = kernel32_SetFilePointerEx(handle, 0, core::ptr::null_mut(), 0);
            assert_eq!(ok, 1, "SetFilePointerEx failed");

            kernel32_CloseHandle(handle);

            // Re-open for reading
            let handle = kernel32_CreateFileW(
                wide_path.as_ptr(),
                0x8000_0000, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX, "CreateFileW (read) failed");

            let mut buf = [0u8; 32];
            let mut bytes_read: u32 = 0;
            let ok = kernel32_ReadFile(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut bytes_read,
                core::ptr::null_mut(),
            );
            assert_eq!(ok, 1, "ReadFile failed");
            assert_eq!(&buf[..bytes_read as usize], data);

            kernel32_CloseHandle(handle);
        }

        // Cleanup
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_move_file_ex_w() {
        let src = "/tmp/litebox_move_src.txt";
        let dst = "/tmp/litebox_move_dst.txt";
        std::fs::write(src, b"move me").unwrap();
        let _ = std::fs::remove_file(dst);

        let wide_src: Vec<u16> = src.encode_utf16().chain(std::iter::once(0u16)).collect();
        let wide_dst: Vec<u16> = dst.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let ok = kernel32_MoveFileExW(wide_src.as_ptr(), wide_dst.as_ptr(), 0);
            assert_eq!(ok, 1, "MoveFileExW failed");
        }

        assert!(!std::path::Path::new(src).exists(), "source still exists");
        assert!(std::path::Path::new(dst).exists(), "destination missing");
        let _ = std::fs::remove_file(dst);
    }

    #[test]
    fn test_remove_directory_w() {
        let dir = "/tmp/litebox_rmdir_test";
        let _ = std::fs::remove_dir(dir);
        std::fs::create_dir(dir).unwrap();

        let wide_dir: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let ok = kernel32_RemoveDirectoryW(wide_dir.as_ptr());
            assert_eq!(ok, 1, "RemoveDirectoryW failed");
        }

        assert!(!std::path::Path::new(dir).exists());
    }

    #[test]
    fn test_nt_write_read_file_handle() {
        // Verify the shared helpers used by ntdll_impl work correctly
        let path = "/tmp/litebox_nt_handle_test.txt";
        let _ = std::fs::remove_file(path);

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        unsafe {
            let handle = kernel32_CreateFileW(
                wide.as_ptr(),
                0x4000_0000 | 0x8000_0000, // GENERIC_READ | GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0x80,
                core::ptr::null_mut(),
            );
            assert_ne!(handle as usize, usize::MAX);

            let data = b"ntdll test";
            let written = nt_write_file_handle(handle as u64, data);
            assert_eq!(written, Some(data.len()));

            // Seek back to start
            kernel32_SetFilePointerEx(handle, 0, core::ptr::null_mut(), 0);

            let mut buf = [0u8; 16];
            let read = nt_read_file_handle(handle as u64, &mut buf);
            assert_eq!(read, Some(data.len()));
            assert_eq!(&buf[..data.len()], data);

            kernel32_CloseHandle(handle);
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_get_command_line_utf8_default() {
        // Before any command line is set, returns empty string
        // (or the value already set by a previous test — we just verify it doesn't panic)
        let s = get_command_line_utf8();
        // Must be a valid UTF-8 string; no assertion on content since OnceLock
        // may have been initialised by an earlier test.
        let _ = s;
    }

    #[test]
    fn test_copy_file_w() {
        let src = "/tmp/litebox_copy_src.txt";
        let dst = "/tmp/litebox_copy_dst.txt";
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
        std::fs::write(src, b"copy test").unwrap();

        let src_wide: Vec<u16> = src.encode_utf16().chain(std::iter::once(0)).collect();
        let dst_wide: Vec<u16> = dst.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            // CopyFileW should succeed
            let result = kernel32_CopyFileW(src_wide.as_ptr(), dst_wide.as_ptr(), 0);
            assert_eq!(result, 1, "CopyFileW should return TRUE");

            // Destination should contain the same content
            let content = std::fs::read(dst).unwrap();
            assert_eq!(content, b"copy test");

            // fail_if_exists = 1 should fail when dst already exists
            let result2 = kernel32_CopyFileW(src_wide.as_ptr(), dst_wide.as_ptr(), 1);
            assert_eq!(result2, 0, "CopyFileW with fail_if_exists=1 should fail");
        }
        let _ = std::fs::remove_file(src);
        let _ = std::fs::remove_file(dst);
    }

    #[test]
    fn test_create_directory_ex_w() {
        let dir = "/tmp/litebox_mkdir_ex_test";
        let _ = std::fs::remove_dir(dir);
        let dir_wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = kernel32_CreateDirectoryExW(
                core::ptr::null(), // template ignored
                dir_wide.as_ptr(),
                core::ptr::null_mut(),
            );
            assert_eq!(result, 1, "CreateDirectoryExW should succeed");
            assert!(std::path::Path::new(dir).is_dir());
        }
        let _ = std::fs::remove_dir(dir);
    }

    #[test]
    fn test_get_full_path_name_w_absolute() {
        let path = "/tmp/litebox_gfpnw_test.txt";
        let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = vec![0u16; 512];

        unsafe {
            let chars = kernel32_GetFullPathNameW(
                path_wide.as_ptr(),
                512,
                buf.as_mut_ptr(),
                core::ptr::null_mut(),
            );
            assert!(
                chars > 0,
                "GetFullPathNameW should return non-zero for valid path"
            );
            let result = String::from_utf16_lossy(&buf[..chars as usize]);
            assert_eq!(result, path, "Absolute path should be returned unchanged");
        }
    }

    #[test]
    fn test_find_first_next_close() {
        let dir = "/tmp/litebox_find_test";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/a.txt"), b"a").unwrap();
        std::fs::write(format!("{dir}/b.txt"), b"b").unwrap();

        let pattern = format!("{dir}/*.txt\0");
        let pattern_wide: Vec<u16> = pattern.encode_utf16().collect();
        // WIN32_FIND_DATAW is 592 bytes
        let mut find_data = vec![0u8; 592];

        unsafe {
            let handle = kernel32_FindFirstFileW(pattern_wide.as_ptr(), find_data.as_mut_ptr());
            assert_ne!(
                handle as usize,
                usize::MAX,
                "FindFirstFileW should return a valid handle"
            );

            // The first file name should be non-empty
            let fname_ptr = find_data.as_ptr().add(44).cast::<u16>();
            let fname_slice = core::slice::from_raw_parts(fname_ptr, 260);
            let fname_len = fname_slice.iter().position(|&c| c == 0).unwrap_or(0);
            assert!(fname_len > 0, "First file name should not be empty");

            // Advance to next entry
            let mut find_data2 = vec![0u8; 592];
            let next = kernel32_FindNextFileW(handle, find_data2.as_mut_ptr());
            // May be 1 (found another .txt) or 0 (no more) — both are valid
            let _ = next;

            let closed = kernel32_FindClose(handle);
            assert_eq!(closed, 1, "FindClose should return TRUE");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_glob_match_patterns() {
        assert!(find_matches_pattern("test.txt", "*"));
        assert!(find_matches_pattern("test.txt", "*.txt"));
        assert!(find_matches_pattern("test.txt", "test.*"));
        assert!(find_matches_pattern("test.txt", "test.txt"));
        assert!(!find_matches_pattern("test.txt", "*.doc"));
        assert!(find_matches_pattern("TEST.TXT", "test.txt"));
        assert!(find_matches_pattern("test.txt", "TEST.TXT"));
        assert!(find_matches_pattern("test.txt", "????.txt"));
        assert!(!find_matches_pattern("test.txt", "?.txt"));
    }

    /// Guard that restores the working directory when dropped.
    struct CwdGuard {
        original: std::path::PathBuf,
    }
    impl CwdGuard {
        fn new() -> Self {
            let original = std::env::current_dir().expect("current_dir should work in tests");
            CwdGuard { original }
        }
    }
    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    #[test]
    fn test_get_full_path_name_w_relative() {
        let tmp_dir = "/tmp/litebox_gfpnw_relative";
        let _ = std::fs::remove_dir_all(tmp_dir);
        std::fs::create_dir_all(tmp_dir).unwrap();

        // Scope the guard so the CWD is restored before the directory is deleted.
        // Without this, concurrent tests that call `current_dir()` may fail because
        // the process CWD would point to a directory that has already been removed.
        {
            let _guard = CwdGuard::new();
            std::env::set_current_dir(tmp_dir).unwrap();

            let path = "test.txt";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 512];

            unsafe {
                let chars = kernel32_GetFullPathNameW(
                    path_wide.as_ptr(),
                    512,
                    buf.as_mut_ptr(),
                    core::ptr::null_mut(),
                );
                assert!(
                    chars > 0,
                    "GetFullPathNameW should return non-zero for relative path"
                );
                let result = String::from_utf16_lossy(&buf[..chars as usize]);
                assert!(
                    result.ends_with(path),
                    "Full path for relative input should end with the relative component"
                );
            }
        } // _guard drops here, restoring the CWD before the directory is deleted

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_get_full_path_name_w_dot() {
        let tmp_dir = "/tmp/litebox_gfpnw_dot";
        let _ = std::fs::remove_dir_all(tmp_dir);
        std::fs::create_dir_all(tmp_dir).unwrap();

        // Scope the guard so the CWD is restored before the directory is deleted.
        {
            let _guard = CwdGuard::new();
            std::env::set_current_dir(tmp_dir).unwrap();

            let path = ".";
            let path_wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
            let mut buf = vec![0u16; 512];

            unsafe {
                let chars = kernel32_GetFullPathNameW(
                    path_wide.as_ptr(),
                    512,
                    buf.as_mut_ptr(),
                    core::ptr::null_mut(),
                );
                assert!(
                    chars > 0,
                    "GetFullPathNameW should return non-zero for '.' (current directory)"
                );
            }
        } // _guard drops here, restoring the CWD before the directory is deleted

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    /// Ensure that FindFirstFileW / FindNextFileW handle cases where metadata
    /// retrieval for a directory entry fails (e.g., a broken symlink) without
    /// panicking or terminating enumeration prematurely.
    #[test]
    fn test_find_first_next_with_inaccessible_entry() {
        let dir = "/tmp/litebox_find_inaccessible_test";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();

        // A normal file that should always be accessible.
        std::fs::write(format!("{dir}/a.txt"), b"a").unwrap();

        // Create a broken symlink that matches the *.txt pattern. On Linux,
        // std::fs::metadata on this path will fail, which exercises the
        // metadata-error skip path in the enumeration logic.
        #[cfg(unix)]
        {
            let broken_target = "/nonexistent/path/for_litebox_test";
            let broken_link = format!("{dir}/broken.txt");
            let _ = std::fs::remove_file(&broken_link);
            // Ignore errors if symlink creation is not supported.
            let _ = std::os::unix::fs::symlink(broken_target, &broken_link);
        }

        let pattern = format!("{dir}/*.txt\0");
        let pattern_wide: Vec<u16> = pattern.encode_utf16().collect();
        let mut find_data = vec![0u8; 592];

        unsafe {
            let handle = kernel32_FindFirstFileW(pattern_wide.as_ptr(), find_data.as_mut_ptr());
            assert_ne!(
                handle as usize,
                usize::MAX,
                "FindFirstFileW should return a valid handle even with problematic entries"
            );

            // Enumerate all matching entries – at least one should be found.
            let mut count = 1usize;
            loop {
                let mut next_data = vec![0u8; 592];
                let next = kernel32_FindNextFileW(handle, next_data.as_mut_ptr());
                if next == 0 {
                    break;
                }
                count += 1;
            }

            assert!(
                count >= 1,
                "Enumeration should yield at least one matching entry"
            );

            let closed = kernel32_FindClose(handle);
            assert_eq!(closed, 1, "FindClose should return TRUE");
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Thread start routine that stores a value via a pointer and returns it.
    unsafe extern "win64" fn thread_fn_store_and_return(param: *mut core::ffi::c_void) -> u32 {
        let p = param.cast::<u32>();
        if !p.is_null() {
            *p = 0xBEEF;
        }
        42
    }

    #[test]
    fn test_create_thread_and_wait_infinite() {
        let mut value: u32 = 0;
        let handle = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut value).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(
            !handle.is_null(),
            "CreateThread should return a non-null handle"
        );

        let result = unsafe { kernel32_WaitForSingleObject(handle, u32::MAX) };
        assert_eq!(result, 0, "WaitForSingleObject should return WAIT_OBJECT_0");
        assert_eq!(value, 0xBEEF, "Thread should have written 0xBEEF");
    }

    #[test]
    fn test_create_thread_with_thread_id() {
        let mut tid: u32 = 0;
        let handle = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                &raw mut tid,
            )
        };
        assert!(
            !handle.is_null(),
            "CreateThread should return a non-null handle"
        );
        assert_ne!(tid, 0, "thread_id should be set to a non-zero value");
        unsafe { kernel32_WaitForSingleObject(handle, u32::MAX) };
    }

    #[test]
    fn test_wait_for_multiple_objects_all() {
        let mut v1: u32 = 0;
        let mut v2: u32 = 0;
        let h1 = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut v1).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        let h2 = unsafe {
            kernel32_CreateThread(
                core::ptr::null_mut(),
                0,
                thread_fn_store_and_return as *mut core::ffi::c_void,
                (&raw mut v2).cast::<core::ffi::c_void>(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h1.is_null() && !h2.is_null());

        let handles = [h1, h2];
        let result = unsafe { kernel32_WaitForMultipleObjects(2, handles.as_ptr(), 1, u32::MAX) };
        assert_eq!(
            result, 0,
            "WaitForMultipleObjects(wait_all) should return WAIT_OBJECT_0"
        );
        assert_eq!(v1, 0xBEEF);
        assert_eq!(v2, 0xBEEF);
    }

    // ── Phase 17: Robustness and Security Tests ─────────────────────────────

    /// Helper: set the sandbox root and return a guard that clears it on drop.
    /// Needed because `SANDBOX_ROOT` is a process-wide `Mutex<Option<String>>`
    /// that must be reset between tests to avoid cross-test interference.
    struct SandboxGuard;
    impl Drop for SandboxGuard {
        fn drop(&mut self) {
            *SANDBOX_ROOT.lock().unwrap() = None;
        }
    }
    fn with_sandbox(root: &str) -> SandboxGuard {
        *SANDBOX_ROOT.lock().unwrap() = Some(root.to_owned());
        SandboxGuard
    }

    /// `sandbox_guard` should leave paths unchanged when no sandbox root is set.
    #[test]
    fn test_sandbox_guard_no_root_passthrough() {
        // Ensure no sandbox is active.
        *SANDBOX_ROOT.lock().unwrap() = None;
        let result = sandbox_guard("/tmp/test/file.txt".to_owned());
        assert_eq!(result, "/tmp/test/file.txt");
    }

    /// `sandbox_guard` should normalise `..` traversals and reject escapes.
    #[test]
    fn test_sandbox_guard_escape_rejected() {
        let _guard = with_sandbox("/sandbox");
        // "/sandbox/../../etc/passwd" normalises to "/etc/passwd" → escapes.
        let result = sandbox_guard("/sandbox/../../etc/passwd".to_owned());
        assert!(
            result.is_empty(),
            "Expected empty string for sandbox escape, got: {result}"
        );
    }

    /// Paths within the sandbox root pass through after normalisation.
    #[test]
    fn test_sandbox_guard_inside_root_passes() {
        let _guard = with_sandbox("/sandbox");
        let result = sandbox_guard("/sandbox/subdir/../file.txt".to_owned());
        assert_eq!(result, "/sandbox/file.txt");
    }

    /// `wide_path_to_linux` returns an empty string when a path escapes the
    /// configured sandbox root.
    #[test]
    fn test_wide_path_to_linux_sandbox_escape_blocked() {
        let _guard = with_sandbox("/sandbox");

        // "C:\..\..\etc\passwd" → "/etc/passwd" which escapes "/sandbox".
        let wide: Vec<u16> = "C:\\..\\..\\etc\\passwd\0".encode_utf16().collect();
        let result = unsafe { wide_path_to_linux(wide.as_ptr()) };
        assert!(
            result.is_empty(),
            "Expected empty string for sandbox escape, got: {result}"
        );
    }

    /// `wide_path_to_linux` returns the normalised path when it stays within
    /// the sandbox root.
    #[test]
    fn test_wide_path_to_linux_sandbox_inside_passes() {
        let _guard = with_sandbox("/sandbox");

        let wide: Vec<u16> = "/sandbox/data/file.txt\0".encode_utf16().collect();
        let result = unsafe { wide_path_to_linux(wide.as_ptr()) };
        assert_eq!(result, "/sandbox/data/file.txt");
    }

    /// `CreateFileW` returns `INVALID_HANDLE_VALUE` with error 4 once
    /// `MAX_OPEN_FILE_HANDLES` handles are open.
    #[test]
    fn test_create_file_handle_limit() {
        const OPEN_EXISTING: u32 = 3;
        const GENERIC_READ: u32 = 0x8000_0000;

        // Ensure no sandbox is active so /dev/null is accessible.
        *SANDBOX_ROOT.lock().unwrap() = None;

        // Use a file that exists on every Linux system.
        let path = "/dev/null\0";
        let wide: Vec<u16> = path.encode_utf16().collect();

        let invalid = usize::MAX as *mut core::ffi::c_void;

        // Open handles until we hit the limit (test limit is 8).
        // We collect them so we can close them afterwards.
        let mut opened: Vec<*mut core::ffi::c_void> = Vec::new();
        let hit_limit = 'fill: {
            for _ in 0..=MAX_OPEN_FILE_HANDLES {
                let h = unsafe {
                    kernel32_CreateFileW(
                        wide.as_ptr(),
                        GENERIC_READ,
                        0,
                        core::ptr::null_mut(),
                        OPEN_EXISTING,
                        0,
                        core::ptr::null_mut(),
                    )
                };
                if h == invalid {
                    break 'fill true;
                }
                opened.push(h);
            }
            false
        };

        // Clean up all handles we opened.
        for h in &opened {
            unsafe { kernel32_CloseHandle(*h) };
        }

        assert!(hit_limit, "Expected the handle limit to be enforced");
        assert_eq!(
            unsafe { kernel32_GetLastError() },
            ERROR_TOO_MANY_OPEN_FILES,
            "Expected ERROR_TOO_MANY_OPEN_FILES"
        );
    }

    /// `CreateFileW` with `desired_access=0` (Windows attribute/metadata query pattern)
    /// must succeed for an existing file and return a valid handle.
    #[test]
    fn test_create_file_metadata_query_desired_access_zero() {
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: usize = usize::MAX;

        let path = "/tmp/litebox_metadata_query_test.txt";
        let _ = std::fs::write(path, b"hello");

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        let h = unsafe {
            kernel32_CreateFileW(
                wide.as_ptr(),
                0, // desired_access=0: attribute/metadata query
                7, // share all
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0x0200_0000, // FILE_FLAG_BACKUP_SEMANTICS
                core::ptr::null_mut(),
            )
        };
        assert_ne!(
            h as usize, INVALID_HANDLE_VALUE,
            "CreateFileW with desired_access=0 should succeed for existing file"
        );
        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(path);
    }

    /// `GetFileInformationByHandle` must fill the `BY_HANDLE_FILE_INFORMATION` struct
    /// (52 bytes / 13 × u32) with valid metadata after opening a file via `CreateFileW`.
    #[test]
    fn test_get_file_information_by_handle() {
        const GENERIC_READ: u32 = 0x8000_0000;
        const OPEN_EXISTING: u32 = 3;
        const INVALID_HANDLE_VALUE: usize = usize::MAX;

        let path = "/tmp/litebox_gfibh_test.txt";
        let content = b"GetFileInformationByHandle test content";
        let _ = std::fs::write(path, content);

        let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0u16)).collect();

        let h = unsafe {
            kernel32_CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                7,
                core::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(h as usize, INVALID_HANDLE_VALUE, "CreateFileW failed");

        // Allocate a zeroed 52-byte BY_HANDLE_FILE_INFORMATION struct.
        let mut info = [0u32; 13];
        let ret = unsafe {
            kernel32_GetFileInformationByHandle(h, info.as_mut_ptr().cast::<core::ffi::c_void>())
        };
        assert_eq!(ret, 1, "GetFileInformationByHandle should return TRUE");

        // dwFileAttributes should be FILE_ATTRIBUTE_NORMAL (0x80) for a regular file.
        assert_eq!(info[0], 0x80, "Expected FILE_ATTRIBUTE_NORMAL");
        // nFileSizeHigh (info[8]) should be 0 for a small file.
        assert_eq!(info[8], 0, "nFileSizeHigh should be 0");
        // nFileSizeLow (info[9]) should equal the content length.
        assert_eq!(
            info[9] as usize,
            content.len(),
            "nFileSizeLow should equal the file size"
        );
        // nNumberOfLinks (info[10]) should be at least 1.
        assert!(info[10] >= 1, "nNumberOfLinks should be >= 1");

        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_get_file_type_stdio() {
        const FILE_TYPE_CHAR: u32 = 2;
        // GetStdHandle pseudo-handles should be reported as FILE_TYPE_CHAR (2).
        let stdin_h = unsafe { kernel32_GetStdHandle(u32::MAX - 9) }; // -10 as u32
        let stdout_h = unsafe { kernel32_GetStdHandle(u32::MAX - 10) }; // -11 as u32
        let stderr_h = unsafe { kernel32_GetStdHandle(u32::MAX - 11) }; // -12 as u32
        assert_eq!(unsafe { kernel32_GetFileType(stdin_h) }, FILE_TYPE_CHAR);
        assert_eq!(unsafe { kernel32_GetFileType(stdout_h) }, FILE_TYPE_CHAR);
        assert_eq!(unsafe { kernel32_GetFileType(stderr_h) }, FILE_TYPE_CHAR);
    }

    #[test]
    fn test_get_file_type_unknown_handle() {
        // An unrecognized handle should be FILE_TYPE_UNKNOWN (0).
        const FILE_TYPE_UNKNOWN: u32 = 0;
        let fake_handle = 0x9999_usize as *mut core::ffi::c_void;
        assert_eq!(
            unsafe { kernel32_GetFileType(fake_handle) },
            FILE_TYPE_UNKNOWN
        );
    }

    #[test]
    fn test_get_system_directory_w() {
        let mut buf = [0u16; 64];
        let len = unsafe { kernel32_GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        assert!(len > 0, "Should return non-zero length");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(
            s.starts_with("C:\\Windows"),
            "Should start with C:\\Windows"
        );
        assert!(s.contains("System32"), "Should contain System32");
    }

    #[test]
    fn test_get_system_directory_w_small_buffer() {
        // A buffer that's too small: should return the required size.
        let mut tiny = [0u16; 3];
        let required =
            unsafe { kernel32_GetSystemDirectoryW(tiny.as_mut_ptr(), tiny.len() as u32) };
        assert!(
            required > tiny.len() as u32,
            "Should return required size when buffer is too small"
        );
    }

    #[test]
    fn test_get_windows_directory_w() {
        let mut buf = [0u16; 32];
        let len = unsafe { kernel32_GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        assert!(len > 0, "Should return non-zero length");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert_eq!(s, "C:\\Windows", "Should return C:\\Windows");
    }

    #[test]
    fn test_format_message_w_known_error() {
        const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;
        let mut buf = [0u16; 256];
        // Error 2 = "The system cannot find the file specified."
        let len = unsafe {
            kernel32_FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                core::ptr::null(),
                2,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert!(len > 0, "Should format error 2");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(s.contains("file"), "Error 2 message should mention 'file'");
    }

    #[test]
    fn test_format_message_w_unknown_error() {
        const FORMAT_MESSAGE_FROM_SYSTEM: u32 = 0x1000;
        let mut buf = [0u16; 256];
        // Error 99999 = not in our table → "Unknown error (...)"
        let len = unsafe {
            kernel32_FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM,
                core::ptr::null(),
                99999,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert!(len > 0, "Should return something for unknown error");
        let s = String::from_utf16_lossy(&buf[..len as usize]);
        assert!(s.contains("Unknown"), "Unknown error should say 'Unknown'");
    }

    #[test]
    fn test_format_message_w_unsupported_flags() {
        // Without FORMAT_MESSAGE_FROM_SYSTEM the function should fail (return 0).
        let mut buf = [0u16; 64];
        let len = unsafe {
            kernel32_FormatMessageW(
                0,
                core::ptr::null(),
                2,
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(len, 0, "Should return 0 for unsupported flags");
    }

    #[test]
    fn test_set_volume_serial_pin() {
        // After set_volume_serial the exact value is returned by get_volume_serial.
        set_volume_serial(0xDEAD_BEEF);
        assert_eq!(get_volume_serial(), 0xDEAD_BEEF);
        // Reset to auto so other tests are not affected.
        set_volume_serial(0);
    }

    #[test]
    fn test_get_volume_serial_auto_nonzero() {
        // With no pinned value get_volume_serial must return something non-zero.
        set_volume_serial(0);
        let serial = get_volume_serial();
        assert_ne!(serial, 0, "Auto-generated serial must be non-zero");
    }

    #[test]
    fn test_get_volume_serial_stable() {
        // Once generated, successive calls should return the same value.
        set_volume_serial(0);
        let first = get_volume_serial();
        let second = get_volume_serial();
        assert_eq!(first, second, "Serial must be stable within a process");
        set_volume_serial(0);
    }

    // ── CreateEventW / SetEvent / ResetEvent / WaitForSingleObject ──────────

    #[test]
    fn test_create_event_returns_nonnull() {
        let handle = unsafe {
            kernel32_CreateEventW(
                core::ptr::null_mut(),
                0, // auto-reset
                0, // not signaled
                core::ptr::null(),
            )
        };
        assert!(
            !handle.is_null(),
            "CreateEventW should return a non-null handle"
        );
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_set_event_signals_waitforsingleobject() {
        // Create an auto-reset event in nonsignaled state.
        let handle =
            unsafe { kernel32_CreateEventW(core::ptr::null_mut(), 0, 0, core::ptr::null()) };
        assert!(!handle.is_null());

        // Signal the event.
        let set_result = unsafe { kernel32_SetEvent(handle) };
        assert_eq!(set_result, 1, "SetEvent should return TRUE");

        // WaitForSingleObject with timeout=0 should succeed immediately.
        let wait_result = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(wait_result, 0, "WAIT_OBJECT_0 expected after SetEvent");

        // Auto-reset: a second wait with timeout=0 should now time out.
        let wait2 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(wait2, 0x0000_0102, "WAIT_TIMEOUT expected (auto-reset)");

        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_manual_reset_event_stays_signaled() {
        // Create a manual-reset event, initially signaled.
        let handle =
            unsafe { kernel32_CreateEventW(core::ptr::null_mut(), 1, 1, core::ptr::null()) };
        assert!(!handle.is_null());

        // Both waits should succeed without resetting.
        let w1 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w1, 0, "First wait should succeed");
        let w2 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(
            w2, 0,
            "Second wait should succeed (manual-reset stays signaled)"
        );

        // After ResetEvent, wait should time out.
        let reset = unsafe { kernel32_ResetEvent(handle) };
        assert_eq!(reset, 1, "ResetEvent should return TRUE");
        let w3 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w3, 0x0000_0102, "WAIT_TIMEOUT expected after ResetEvent");

        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_set_reset_event_on_invalid_handle() {
        let bad: *mut core::ffi::c_void = 0xDEAD_BEEF as *mut _;
        let set_result = unsafe { kernel32_SetEvent(bad) };
        assert_eq!(
            set_result, 0,
            "SetEvent on invalid handle should return FALSE"
        );
        let reset_result = unsafe { kernel32_ResetEvent(bad) };
        assert_eq!(
            reset_result, 0,
            "ResetEvent on invalid handle should return FALSE"
        );
    }

    #[test]
    fn test_get_exit_code_process_still_active() {
        let mut exit_code: u32 = 0;
        // Use the current-process pseudo-handle returned by GetCurrentProcess.
        let current_process = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_GetExitCodeProcess(current_process, &raw mut exit_code) };
        assert_eq!(result, 1, "GetExitCodeProcess should return TRUE");
        assert_eq!(exit_code, 259, "exit code should be STILL_ACTIVE (259)");
    }

    #[test]
    fn test_get_exit_code_process_null_out_ptr() {
        // NULL output pointer should not crash for the current-process pseudo-handle
        let current_process = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_GetExitCodeProcess(current_process, core::ptr::null_mut()) };
        assert_eq!(
            result, 1,
            "GetExitCodeProcess should return TRUE even with null exit_code"
        );
    }

    #[test]
    fn test_get_exit_code_process_invalid_handle() {
        let mut exit_code: u32 = 999;
        // NULL is not the current-process pseudo-handle; should return FALSE + ERROR_INVALID_HANDLE.
        let result =
            unsafe { kernel32_GetExitCodeProcess(core::ptr::null_mut(), &raw mut exit_code) };
        assert_eq!(result, 0, "GetExitCodeProcess(NULL) should return FALSE");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 6, "last error should be ERROR_INVALID_HANDLE (6)");
        // exit_code must not have been modified.
        assert_eq!(exit_code, 999, "exit_code should be unchanged on failure");
    }

    #[test]
    fn test_set_file_attributes_w_readonly() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("litebox_attr_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("test_attr.txt");
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(b"hello").unwrap();
        drop(f);

        // Record the original mode to verify we don't disturb group/other bits.
        let original_mode = std::fs::metadata(&file_path).unwrap().permissions().mode();

        // Build wide path
        let path_str = file_path.to_string_lossy();
        let wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();

        // Set read-only: only owner write bit should be cleared; group/other unchanged.
        let r = unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0001) }; // FILE_ATTRIBUTE_READONLY
        assert_eq!(r, 1, "SetFileAttributesW(READONLY) should return TRUE");
        let readonly_mode = std::fs::metadata(&file_path).unwrap().permissions().mode();
        assert_eq!(
            readonly_mode & 0o200,
            0,
            "owner write bit should be cleared"
        );
        // Group/other write bits must not have changed.
        assert_eq!(
            readonly_mode & 0o022,
            original_mode & 0o022,
            "group/other write bits must not be changed when setting READONLY"
        );

        // Clear read-only: owner write bit should be restored; group/other unchanged.
        let r2 = unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0080) }; // FILE_ATTRIBUTE_NORMAL
        assert_eq!(r2, 1, "SetFileAttributesW(NORMAL) should return TRUE");
        let restored_mode = std::fs::metadata(&file_path).unwrap().permissions().mode();
        assert_ne!(
            restored_mode & 0o200,
            0,
            "owner write bit should be restored"
        );
        assert_eq!(
            restored_mode & 0o022,
            original_mode & 0o022,
            "group/other write bits must not be broadened beyond original"
        );

        let _ = std::fs::remove_file(&file_path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_set_file_attributes_w_nonexistent() {
        let wide: Vec<u16> = "/nonexistent_litebox_xyz/file.txt\0"
            .encode_utf16()
            .collect();
        let r = unsafe { kernel32_SetFileAttributesW(wide.as_ptr(), 0x0001) };
        assert_eq!(
            r, 0,
            "SetFileAttributesW on nonexistent path should return FALSE"
        );
    }

    #[test]
    fn test_get_module_file_name_w_current_exe() {
        let mut buf = vec![0u16; 1024];
        let written = unsafe {
            kernel32_GetModuleFileNameW(core::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32)
        };
        assert!(
            written > 0,
            "GetModuleFileNameW should return > 0 chars for current exe"
        );
        // Null-terminated at `written`
        assert_eq!(buf[written as usize], 0, "buffer should be null-terminated");
        let path = String::from_utf16_lossy(&buf[..written as usize]);
        assert!(!path.is_empty(), "exe path should not be empty");
    }

    #[test]
    fn test_get_module_file_name_w_null_buffer() {
        // NOTE: This is an intentional, non-Windows-compatible behaviour.
        // On Windows, GetModuleFileNameW with nSize=0 and a null buffer returns 0
        // and sets an error (it does NOT have "required length" semantics).
        // In this shim we instead return the required length (including the null
        // terminator), matching GetEnvironmentVariableW-style semantics to make
        // callers easier to write.
        let result =
            unsafe { kernel32_GetModuleFileNameW(core::ptr::null_mut(), core::ptr::null_mut(), 0) };
        // The required length must be > 0 because /proc/self/exe has a non-empty path.
        assert!(
            result > 0,
            "In this shim, GetModuleFileNameW with size=0 returns the required buffer length (> 0)"
        );
    }

    /// Verify that `dll_basename` correctly extracts filenames from Windows-style
    /// paths, POSIX paths, bare names, and edge cases.
    #[test]
    fn test_dll_basename() {
        assert_eq!(dll_basename("kernel32.dll"), "kernel32.dll");
        assert_eq!(
            dll_basename("C:\\Windows\\System32\\kernel32.dll"),
            "kernel32.dll"
        );
        assert_eq!(
            dll_basename("C:\\Windows\\System32\\kernel32.dll\\"),
            "kernel32.dll"
        );
        assert_eq!(dll_basename("/usr/local/lib/foo.dll"), "foo.dll");
        assert_eq!(dll_basename("foo.dll\\"), "foo.dll");
        assert_eq!(dll_basename("foo.dll"), "foo.dll");
    }

    /// Verify that `LoadLibraryA` strips a full Windows-style path down to the
    /// basename before doing the registry lookup.
    #[test]
    fn test_load_library_a_with_windows_path() {
        let exports = vec![(
            "WINPATHDLL.DLL".to_string(),
            "WinFunc".to_string(),
            0xABCD_1234_usize,
        )];
        register_dynamic_exports(&exports);

        // Pass a full Windows-style path; only the basename should be looked up.
        let name = b"C:\\Windows\\System32\\winpathdll.dll\0";
        let handle = unsafe { kernel32_LoadLibraryA(name.as_ptr()) } as usize;
        assert_ne!(
            handle, 0,
            "LoadLibraryA should return a non-null handle for a full Windows path"
        );
    }

    #[test]
    fn test_load_library_and_get_proc_address() {
        // Register a fake DLL with one export
        let exports = vec![(
            "TESTDLL.DLL".to_string(),
            "TestFunc".to_string(),
            0xDEAD_BEEF_usize,
        )];
        register_dynamic_exports(&exports);

        // LoadLibraryA should find the registered DLL (case-insensitive)
        let name = b"testdll.dll\0";
        let handle = unsafe { kernel32_LoadLibraryA(name.as_ptr()) } as usize;
        assert_ne!(handle, 0, "LoadLibraryA should return a non-null handle");

        // GetProcAddress should find the exported function
        let func_name = b"TestFunc\0";
        let addr =
            unsafe { kernel32_GetProcAddress(handle as *mut _, func_name.as_ptr()) } as usize;
        assert_eq!(
            addr, 0xDEAD_BEEF_usize,
            "GetProcAddress should return the registered address"
        );

        // GetProcAddress for an unknown function should return NULL
        let bad_name = b"NoSuchFunc\0";
        let bad_addr = unsafe { kernel32_GetProcAddress(handle as *mut _, bad_name.as_ptr()) };
        assert!(
            bad_addr.is_null(),
            "GetProcAddress for unknown function should return NULL"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 127, "GetLastError should be ERROR_PROC_NOT_FOUND");
    }

    #[test]
    fn test_load_library_unknown_dll_returns_null() {
        let name = b"NOTREGISTERED_XYZ.DLL\0";
        let handle = unsafe { kernel32_LoadLibraryA(name.as_ptr()) };
        assert!(
            handle.is_null(),
            "LoadLibraryA for unknown DLL should return NULL"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 126, "GetLastError should be ERROR_MOD_NOT_FOUND");
    }

    #[test]
    fn test_load_library_w_with_path() {
        // Register a DLL first
        let exports = vec![(
            "PATHDLL.DLL".to_string(),
            "PathFunc".to_string(),
            0x1234_5678_usize,
        )];
        register_dynamic_exports(&exports);

        // LoadLibraryW should strip the path and find the DLL by basename.
        // Test with a full Windows-style path (uses '\\' separators) to verify
        // that the Windows-aware basename extraction works on Linux.
        let wide_name: Vec<u16> = "C:\\Windows\\System32\\pathdll.dll\0"
            .encode_utf16()
            .collect();
        let handle = unsafe { kernel32_LoadLibraryW(wide_name.as_ptr()) } as usize;
        assert_ne!(
            handle, 0,
            "LoadLibraryW should return a non-null handle for a full Windows path"
        );
    }

    #[test]
    fn test_get_module_handle_w_named() {
        // Register a known DLL
        let exports = vec![(
            "HANDLETEST.DLL".to_string(),
            "SomeFunc".to_string(),
            0xCAFE_BABE_usize,
        )];
        register_dynamic_exports(&exports);

        let wide_name: Vec<u16> = "handletest.dll\0".encode_utf16().collect();
        let handle = unsafe { kernel32_GetModuleHandleW(wide_name.as_ptr()) };
        assert!(
            !handle.is_null(),
            "GetModuleHandleW should find the registered DLL"
        );
    }

    #[test]
    fn test_get_module_handle_w_null_returns_base() {
        let handle = unsafe { kernel32_GetModuleHandleW(core::ptr::null()) } as usize;
        assert_eq!(
            handle, 0x400000,
            "GetModuleHandleW(NULL) should return the main module base"
        );
    }

    #[test]
    fn test_create_hard_link_w_source_not_found() {
        // Linking to a non-existent source should fail
        let src: Vec<u16> = "C:\\nonexistent_src_12345.txt\0".encode_utf16().collect();
        let dst: Vec<u16> = "C:\\nonexistent_dst_12345.txt\0".encode_utf16().collect();
        let result =
            unsafe { kernel32_CreateHardLinkW(dst.as_ptr(), src.as_ptr(), core::ptr::null_mut()) };
        assert_eq!(result, 0, "CreateHardLinkW should fail for missing source");
    }

    #[test]
    fn test_create_symbolic_link_w_already_exists() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let target = dir.join("litebox_test_symlink_target.txt");
        let link = dir.join("litebox_test_symlink_link.txt");
        // Clean up in case left over from a previous run
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
        // Create the target file
        let mut f = std::fs::File::create(&target).unwrap();
        f.write_all(b"hello").unwrap();

        // First symlink should succeed
        let target_wide: Vec<u16> = format!("{}\0", target.display()).encode_utf16().collect();
        let link_wide: Vec<u16> = format!("{}\0", link.display()).encode_utf16().collect();
        let r1 =
            unsafe { kernel32_CreateSymbolicLinkW(link_wide.as_ptr(), target_wide.as_ptr(), 0) };
        assert_eq!(r1, 1, "First CreateSymbolicLinkW should succeed");
        assert!(
            link.exists() || link.symlink_metadata().is_ok(),
            "symlink should exist"
        );

        // Second call with the same link path should fail (already exists)
        let r2 =
            unsafe { kernel32_CreateSymbolicLinkW(link_wide.as_ptr(), target_wide.as_ptr(), 0) };
        assert_eq!(
            r2, 0,
            "CreateSymbolicLinkW should fail when link already exists"
        );

        // Clean up
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    /// `GetProcAddress` called with an ordinal (proc_name value < 0x10000) must
    /// return NULL and set `ERROR_PROC_NOT_FOUND` (127).  Windows encodes ordinals
    /// as small integers below the 64 KB boundary; this shim does not support
    /// ordinal-based lookup.
    #[test]
    fn test_get_proc_address_ordinal() {
        // Use any non-null handle; the ordinal path exits before the handle lookup.
        let fake_handle = 0x1_0000 as *mut core::ffi::c_void;
        // Ordinal 1 as a pointer value (< 0x10000). Using dangling() gives value 1
        // (align_of::<u8>() == 1) without triggering the manual_dangling_ptr lint.
        let ordinal_ptr = std::ptr::dangling::<u8>();
        let result = unsafe { kernel32_GetProcAddress(fake_handle, ordinal_ptr) };
        assert!(
            result.is_null(),
            "GetProcAddress with ordinal should return NULL"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(
            err, 127,
            "GetLastError should be ERROR_PROC_NOT_FOUND (127) for ordinal input"
        );
    }

    /// `GetProcAddress` called with a handle that was never returned by
    /// `LoadLibraryA/W` or `GetModuleHandleA/W` must return NULL and set
    /// `ERROR_PROC_NOT_FOUND` (127).
    #[test]
    fn test_get_proc_address_invalid_handle() {
        // A handle value that is deliberately not in the DLL registry.
        let bogus_handle = 0xDEAD_C0DE_usize as *mut core::ffi::c_void;
        let func_name = b"SomeFunction\0";
        let result = unsafe { kernel32_GetProcAddress(bogus_handle, func_name.as_ptr()) };
        assert!(
            result.is_null(),
            "GetProcAddress with invalid handle should return NULL"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(
            err, 127,
            "GetLastError should be ERROR_PROC_NOT_FOUND (127) for invalid handle"
        );
    }

    /// `CreatePipe` must create two functional handles where writing to the write end
    /// is readable from the read end.
    #[test]
    fn test_create_pipe_read_write() {
        let mut read_handle: *mut core::ffi::c_void = core::ptr::null_mut();
        let mut write_handle: *mut core::ffi::c_void = core::ptr::null_mut();

        let result = unsafe {
            kernel32_CreatePipe(
                &raw mut read_handle,
                &raw mut write_handle,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(result, 1, "CreatePipe should return TRUE");
        assert!(!read_handle.is_null(), "read handle must not be null");
        assert!(!write_handle.is_null(), "write handle must not be null");

        // Write to the write end.
        let data = b"hello pipe";
        let mut bytes_written: u32 = 0;
        let wr = unsafe {
            kernel32_WriteFile(
                write_handle,
                data.as_ptr(),
                data.len() as u32,
                &raw mut bytes_written,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(wr, 1, "WriteFile to write end should succeed");
        assert_eq!(bytes_written as usize, data.len());

        // Close the write end so the read side can detect EOF.
        unsafe { kernel32_CloseHandle(write_handle) };

        // Read from the read end.
        let mut buf = [0u8; 16];
        let mut bytes_read: u32 = 0;
        let rd = unsafe {
            kernel32_ReadFile(
                read_handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut bytes_read,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rd, 1, "ReadFile from read end should succeed");
        assert_eq!(&buf[..bytes_read as usize], data);

        unsafe { kernel32_CloseHandle(read_handle) };
    }

    /// `CreatePipe` with a null `read_pipe` pointer should fail.
    #[test]
    fn test_create_pipe_null_read_ptr() {
        let mut write_handle: *mut core::ffi::c_void = core::ptr::null_mut();
        let result = unsafe {
            kernel32_CreatePipe(
                core::ptr::null_mut(),
                &raw mut write_handle,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(result, 0, "CreatePipe should fail with null read_pipe");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 87, "ERROR_INVALID_PARAMETER (87) expected");
    }

    /// `DuplicateHandle` on a file handle should produce an independent clone that
    /// can still be used after the original is closed.
    #[test]
    fn test_duplicate_handle_file() {
        let dir = std::env::temp_dir().join(format!("litebox_dup_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("dup_test.txt");

        let path_wide: Vec<u16> = file_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // Open a file for writing.
        let orig = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x4000_0000u32, // GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(
            orig,
            usize::MAX as *mut core::ffi::c_void,
            "CreateFileW should succeed"
        );

        let mut dup: *mut core::ffi::c_void = core::ptr::null_mut();
        let result = unsafe {
            kernel32_DuplicateHandle(
                usize::MAX as *mut core::ffi::c_void, // current process
                orig,
                usize::MAX as *mut core::ffi::c_void, // current process
                &raw mut dup,
                0,
                0,
                0,
            )
        };
        assert_eq!(result, 1, "DuplicateHandle should return TRUE");
        assert!(!dup.is_null(), "duplicate handle must not be null");

        // Close the original; the duplicate should still work.
        unsafe { kernel32_CloseHandle(orig) };

        let text = b"dup works";
        let mut written: u32 = 0;
        let wr = unsafe {
            kernel32_WriteFile(
                dup,
                text.as_ptr(),
                text.len() as u32,
                &raw mut written,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(wr, 1, "WriteFile through duplicate should succeed");
        assert_eq!(written as usize, text.len());

        unsafe { kernel32_CloseHandle(dup) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `DuplicateHandle` with a null `target_handle` must return FALSE with
    /// `ERROR_INVALID_PARAMETER`.
    #[test]
    fn test_duplicate_handle_null_target() {
        let fake_src = 0x1_0000 as *mut core::ffi::c_void;
        let result = unsafe {
            kernel32_DuplicateHandle(
                core::ptr::null_mut(),
                fake_src,
                core::ptr::null_mut(),
                core::ptr::null_mut(), // null target — should fail
                0,
                0,
                0,
            )
        };
        assert_eq!(result, 0, "DuplicateHandle with null target must fail");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 87, "ERROR_INVALID_PARAMETER (87) expected");
    }

    /// `CreateFileMappingA` on `INVALID_HANDLE_VALUE` followed by `MapViewOfFile`
    /// and `UnmapViewOfFile` must round-trip correctly for an anonymous mapping.
    #[test]
    fn test_create_file_mapping_anonymous() {
        // INVALID_HANDLE_VALUE = usize::MAX as *mut c_void
        let invalid = usize::MAX as *mut core::ffi::c_void;
        let mapping = unsafe {
            kernel32_CreateFileMappingA(
                invalid,
                core::ptr::null_mut(),
                4,    // PAGE_READWRITE
                0,    // size_high
                4096, // size_low = 4 KiB
                core::ptr::null(),
            )
        };
        assert!(
            !mapping.is_null(),
            "CreateFileMappingA should return a handle"
        );

        let view = unsafe {
            kernel32_MapViewOfFile(
                mapping, 4, // FILE_MAP_WRITE
                0, 0, // offset = 0
                4096,
            )
        };
        assert!(!view.is_null(), "MapViewOfFile should succeed");

        // Write and read back through the mapped view.
        unsafe {
            *(view.cast::<u32>()) = 0xDEAD_BEEF;
            assert_eq!(*(view.cast::<u32>()), 0xDEAD_BEEF);
        }

        let unmap = unsafe { kernel32_UnmapViewOfFile(view) };
        assert_eq!(unmap, 1, "UnmapViewOfFile should return TRUE");
    }

    /// `GetFinalPathNameByHandleW` must return the correct path for an open file.
    #[test]
    fn test_get_final_path_name_by_handle_w() {
        let dir = std::env::temp_dir().join(format!("litebox_final_path_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("final_path.txt");
        std::fs::write(&file_path, b"test").unwrap();

        let path_wide: Vec<u16> = file_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000u32, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(
            handle,
            usize::MAX as *mut core::ffi::c_void,
            "CreateFileW should succeed"
        );

        let mut buf = [0u16; 512];
        let len = unsafe {
            kernel32_GetFinalPathNameByHandleW(handle, buf.as_mut_ptr(), buf.len() as u32, 0)
        };
        assert!(
            len > 0,
            "GetFinalPathNameByHandleW should return a non-zero length"
        );

        let returned_path: String = String::from_utf16_lossy(
            &buf[..len as usize], // len does not include the null terminator
        );
        // The returned path must end with the file name.
        assert!(
            returned_path.ends_with("final_path.txt"),
            "Returned path '{returned_path}' should end with 'final_path.txt'"
        );

        unsafe { kernel32_CloseHandle(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `GetFileInformationByHandleEx` with FileBasicInfo (class 0) should fill the
    /// buffer without returning an error for a real file.
    #[test]
    fn test_get_file_information_by_handle_ex_basic() {
        let dir = std::env::temp_dir().join(format!("litebox_file_info_ex_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("info_ex.txt");
        std::fs::write(&file_path, b"hello").unwrap();

        let path_wide: Vec<u16> = file_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000u32,
                0,
                core::ptr::null_mut(),
                3,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(handle, usize::MAX as *mut core::ffi::c_void);

        let mut buf = [0u8; 40];
        let result = unsafe {
            kernel32_GetFileInformationByHandleEx(
                handle,
                0, // FileBasicInfo
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                buf.len() as u32,
            )
        };
        assert_eq!(result, 1, "FileBasicInfo query should succeed");

        // FileAttributes at offset 32 should be FILE_ATTRIBUTE_NORMAL (0x80) since
        // the file is writable.
        let attrs = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert!(
            attrs == 0x80 || attrs == 0x01,
            "FileAttributes should be NORMAL (0x80) or READONLY (0x01), got {attrs:#x}"
        );

        unsafe { kernel32_CloseHandle(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `GetFileInformationByHandleEx` with FileStandardInfo (class 1) should return
    /// the correct file size.
    #[test]
    fn test_get_file_information_by_handle_ex_standard() {
        let dir =
            std::env::temp_dir().join(format!("litebox_file_info_std_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file_path = dir.join("info_std.txt");
        std::fs::write(&file_path, b"hello world").unwrap();

        let path_wide: Vec<u16> = file_path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000u32,
                0,
                core::ptr::null_mut(),
                3,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(handle, usize::MAX as *mut core::ffi::c_void);

        let mut buf = [0u8; 24];
        let result = unsafe {
            kernel32_GetFileInformationByHandleEx(
                handle,
                1, // FileStandardInfo
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                buf.len() as u32,
            )
        };
        assert_eq!(result, 1, "FileStandardInfo query should succeed");

        // EndOfFile is at offset 8 and should equal 11 (len("hello world")).
        let end_of_file = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(end_of_file, 11, "EndOfFile should be 11");

        // Directory flag at offset 21 should be 0 (file, not directory).
        assert_eq!(buf[21], 0, "Directory flag should be 0 for a regular file");

        unsafe { kernel32_CloseHandle(handle) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `InitializeProcThreadAttributeList(null, …)` should set `*size` and return FALSE.
    /// `InitializeProcThreadAttributeList(non_null, …)` should return TRUE.
    #[test]
    fn test_initialize_proc_thread_attribute_list() {
        let mut required_size: usize = 0;

        // Size query: attribute_list = null.
        let r1 = unsafe {
            kernel32_InitializeProcThreadAttributeList(
                core::ptr::null_mut(),
                1,
                0,
                &raw mut required_size,
            )
        };
        assert_eq!(r1, 0, "Size query should return FALSE");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(
            err, 122,
            "ERROR_INSUFFICIENT_BUFFER (122) expected on size query"
        );
        assert!(required_size > 0, "Required size must be non-zero");

        // Actual initialization with a properly-sized buffer.
        let mut buf = vec![0u8; required_size];
        let r2 = unsafe {
            kernel32_InitializeProcThreadAttributeList(
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                1,
                0,
                &raw mut required_size,
            )
        };
        assert_eq!(r2, 1, "Initialization with valid buffer should return TRUE");
    }

    /// `CancelIo` should return TRUE for any handle since all I/O is synchronous.
    #[test]
    fn test_cancel_io_returns_true() {
        let result = unsafe { kernel32_CancelIo(0x1234 as *mut core::ffi::c_void) };
        assert_eq!(result, 1, "CancelIo should return TRUE");
        let result_null = unsafe { kernel32_CancelIo(core::ptr::null_mut()) };
        assert_eq!(
            result_null, 1,
            "CancelIo should return TRUE even for null handle"
        );
    }

    /// `UpdateProcThreadAttribute` should return TRUE.
    #[test]
    fn test_update_proc_thread_attribute_returns_true() {
        let result = unsafe {
            kernel32_UpdateProcThreadAttribute(
                0x1000 as *mut core::ffi::c_void,
                0,
                0x20007, // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
                0x2000 as *mut core::ffi::c_void,
                8,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 1, "UpdateProcThreadAttribute should return TRUE");
    }

    /// `VirtualQuery` must return MBI_SIZE (48) and fill in sensible fields for
    /// an address that is definitely mapped (the stack or heap is always mapped).
    #[test]
    fn test_virtual_query_mapped_address() {
        const MBI_SIZE: usize = 48;
        let mut buf = [0u8; MBI_SIZE];
        // Query an address that we know is mapped: the buffer itself.
        let addr = buf.as_ptr().cast::<core::ffi::c_void>();
        let ret = unsafe { kernel32_VirtualQuery(addr, buf.as_mut_ptr(), MBI_SIZE) };
        assert_eq!(
            ret, MBI_SIZE,
            "VirtualQuery should return 48 for a mapped address"
        );

        // BaseAddress should be non-zero and ≤ the queried address.
        let base = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert!(base > 0, "BaseAddress should be non-zero");
        assert!(
            base <= addr as u64,
            "BaseAddress should be ≤ the queried address"
        );

        // RegionSize should be > 0.
        let region_size = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        assert!(region_size > 0, "RegionSize should be > 0");

        // State should be MEM_COMMIT (0x1000).
        let state = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(state, 0x1000, "State should be MEM_COMMIT");
    }

    /// `VirtualQuery` on an unmapped address should return MBI_SIZE with
    /// State == MEM_FREE (0x10000).
    #[test]
    fn test_virtual_query_unmapped_address() {
        const MBI_SIZE: usize = 48;
        let mut buf = [0u8; MBI_SIZE];
        // Use a very low address that is almost certainly not mapped.
        let addr = 0x1000usize as *const core::ffi::c_void;
        let ret = unsafe { kernel32_VirtualQuery(addr, buf.as_mut_ptr(), MBI_SIZE) };
        assert_eq!(
            ret, MBI_SIZE,
            "VirtualQuery should return 48 even for unmapped address"
        );
        let state = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(
            state, 0x10000,
            "State should be MEM_FREE for unmapped address"
        );
    }

    /// `VirtualQuery` with a buffer that is too small should return 0.
    #[test]
    fn test_virtual_query_buffer_too_small() {
        let mut buf = [0u8; 16]; // smaller than MBI_SIZE (48)
        let addr = buf.as_ptr().cast::<core::ffi::c_void>();
        let ret = unsafe { kernel32_VirtualQuery(addr, buf.as_mut_ptr(), 16) };
        assert_eq!(
            ret, 0,
            "VirtualQuery should return 0 when buffer is too small"
        );
    }

    /// `LockFileEx` with an invalid handle should return FALSE and set
    /// `ERROR_INVALID_HANDLE` (6).
    #[test]
    fn test_lock_file_ex_invalid_handle() {
        let result = unsafe {
            kernel32_LockFileEx(
                0xDEAD as *mut core::ffi::c_void, // bogus handle
                0,                                // LOCK_SH, may block
                0,
                0,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(
            result, 0,
            "LockFileEx with invalid handle must return FALSE"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(
            err, 6,
            "LockFileEx with invalid handle must set ERROR_INVALID_HANDLE"
        );
    }

    /// `LockFileEx` on a real file handle should succeed and `UnlockFile`
    /// should release the lock.
    #[test]
    fn test_lock_file_ex_and_unlock() {
        // Create a temporary file to lock.
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        let tmp_path = std::env::temp_dir().join("litebox_test_lock.tmp");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .expect("open tmp file");
        let _ = std::fs::remove_file(&tmp_path); // unlink path; fd stays open

        let handle_val = alloc_file_handle();
        with_file_handles(|map| {
            map.insert(handle_val, FileEntry::new(file));
        });
        let handle = handle_val as *mut core::ffi::c_void;

        // Acquire a shared lock (non-blocking).
        let lock_result = unsafe {
            kernel32_LockFileEx(
                handle,
                LOCKFILE_FAIL_IMMEDIATELY,
                0,
                0,
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(lock_result, 1, "LockFileEx should succeed on real file");

        // Release the lock.
        let unlock_result = unsafe { kernel32_UnlockFile(handle, 0, 0, 0, 0) };
        assert_eq!(unlock_result, 1, "UnlockFile should succeed on locked file");

        // Clean up.
        with_file_handles(|map| {
            map.remove(&handle_val);
        });
    }

    /// `SystemTimeToFileTime` should return FALSE for out-of-range SYSTEMTIME fields.
    #[test]
    fn test_system_time_to_file_time_invalid_input() {
        let mut ft = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        // Invalid month (0)
        let st_bad = SystemTime {
            w_year: 2024,
            w_month: 0, // invalid
            w_day: 1,
            w_day_of_week: 0,
            w_hour: 0,
            w_minute: 0,
            w_second: 0,
            w_milliseconds: 0,
        };
        let result = unsafe {
            kernel32_SystemTimeToFileTime(
                core::ptr::addr_of!(st_bad).cast::<u8>(),
                core::ptr::addr_of_mut!(ft),
            )
        };
        assert_eq!(result, 0, "Invalid month=0 should return FALSE");

        // Invalid year (before FILETIME epoch: 1601)
        let st_early = SystemTime {
            w_year: 1600,
            w_month: 1,
            w_day: 1,
            w_day_of_week: 0,
            w_hour: 0,
            w_minute: 0,
            w_second: 0,
            w_milliseconds: 0,
        };
        let result2 = unsafe {
            kernel32_SystemTimeToFileTime(
                core::ptr::addr_of!(st_early).cast::<u8>(),
                core::ptr::addr_of_mut!(ft),
            )
        };
        assert_eq!(result2, 0, "Year < 1601 should return FALSE");
    }

    /// `LocalFree` should return NULL on success and the original pointer on failure.
    #[test]
    fn test_local_free_success_and_failure() {
        // Allocate a block and free it — LocalFree should return NULL.
        let ptr = unsafe { kernel32_LocalAlloc(0, 16) };
        assert!(!ptr.is_null());
        let result = unsafe { kernel32_LocalFree(ptr) };
        assert!(result.is_null(), "LocalFree should return NULL on success");

        // Passing NULL: HeapFree returns TRUE for NULL (no-op), so LocalFree returns NULL.
        let result_null = unsafe { kernel32_LocalFree(core::ptr::null_mut()) };
        assert!(
            result_null.is_null(),
            "LocalFree(NULL) should return NULL (no-op)"
        );
    }

    // ── Phase 26 tests ────────────────────────────────────────────────────
    #[test]
    fn test_create_mutex_and_release() {
        let handle = unsafe { kernel32_CreateMutexW(core::ptr::null_mut(), 0, core::ptr::null()) };
        assert!(!handle.is_null());
        let wait_result = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(
            wait_result, 0,
            "WaitForSingleObject on unowned mutex should return WAIT_OBJECT_0"
        );
        let release_result = unsafe { kernel32_ReleaseMutex(handle) };
        assert_eq!(release_result, 1, "ReleaseMutex should return TRUE");
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_mutex_recursive_acquire() {
        let handle = unsafe { kernel32_CreateMutexW(core::ptr::null_mut(), 1, core::ptr::null()) };
        assert!(!handle.is_null());
        let wait_result = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(
            wait_result, 0,
            "Recursive mutex acquire should return WAIT_OBJECT_0"
        );
        let r1 = unsafe { kernel32_ReleaseMutex(handle) };
        assert_eq!(r1, 1);
        let r2 = unsafe { kernel32_ReleaseMutex(handle) };
        assert_eq!(r2, 1);
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_open_mutex_not_found_error_code() {
        // OpenMutexW on an unknown name must set ERROR_FILE_NOT_FOUND (2).
        let name: Vec<u16> = "NonExistentMutex999\0".encode_utf16().collect();
        let h = unsafe { kernel32_OpenMutexW(0x001F_0001, 0, name.as_ptr()) };
        assert!(
            h.is_null(),
            "OpenMutexW should return NULL for unknown name"
        );
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 2, "Should be ERROR_FILE_NOT_FOUND (2)");
    }

    #[test]
    fn test_create_semaphore_and_release() {
        let handle =
            unsafe { kernel32_CreateSemaphoreW(core::ptr::null_mut(), 0, 5, core::ptr::null()) };
        assert!(!handle.is_null());
        let mut prev: i32 = -1;
        let result = unsafe { kernel32_ReleaseSemaphore(handle, 2, core::ptr::addr_of_mut!(prev)) };
        assert_eq!(result, 1);
        assert_eq!(prev, 0, "Previous count should be 0");
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_semaphore_release_invalid_handle_error() {
        // ReleaseSemaphore on a bogus handle must set ERROR_INVALID_HANDLE (6).
        let bogus = 0xDEAD_BEEF_usize as *mut core::ffi::c_void;
        let result = unsafe { kernel32_ReleaseSemaphore(bogus, 1, core::ptr::null_mut()) };
        assert_eq!(result, 0, "Should fail on bogus handle");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 6, "Should be ERROR_INVALID_HANDLE (6)");
    }

    #[test]
    fn test_semaphore_release_too_many_posts() {
        // Releasing beyond max_count must set ERROR_TOO_MANY_POSTS (298).
        let handle =
            unsafe { kernel32_CreateSemaphoreW(core::ptr::null_mut(), 3, 3, core::ptr::null()) };
        assert!(!handle.is_null());
        let result = unsafe { kernel32_ReleaseSemaphore(handle, 1, core::ptr::null_mut()) };
        assert_eq!(result, 0, "Should fail when exceeding max_count");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 298, "Should be ERROR_TOO_MANY_POSTS (298)");
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_semaphore_wait_and_release() {
        let handle =
            unsafe { kernel32_CreateSemaphoreW(core::ptr::null_mut(), 2, 5, core::ptr::null()) };
        assert!(!handle.is_null());
        let w1 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w1, 0);
        let w2 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w2, 0);
        let w3 = unsafe { kernel32_WaitForSingleObject(handle, 0) };
        assert_eq!(w3, 0x102, "Should return WAIT_TIMEOUT");
        unsafe { kernel32_CloseHandle(handle) };
    }

    #[test]
    fn test_set_console_mode_returns_true() {
        let result = unsafe { kernel32_SetConsoleMode(core::ptr::null_mut(), 0x0007) };
        assert_eq!(result, 1);
    }

    #[test]
    fn test_set_get_console_title() {
        let title: Vec<u16> = "TestTitle\0".encode_utf16().collect();
        let set_result = unsafe { kernel32_SetConsoleTitleW(title.as_ptr()) };
        assert_eq!(set_result, 1);
        let mut buf = vec![0u16; 64];
        let got = unsafe { kernel32_GetConsoleTitleW(buf.as_mut_ptr(), 64) };
        assert!(got > 0);
        let s: String = buf[..got as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert_eq!(s, "TestTitle");
    }

    #[test]
    fn test_alloc_free_console() {
        assert_eq!(unsafe { kernel32_AllocConsole() }, 1);
        assert_eq!(unsafe { kernel32_FreeConsole() }, 1);
    }

    #[test]
    fn test_lstrlen_a() {
        let s = b"hello\0";
        let len = unsafe { kernel32_lstrlenA(s.as_ptr()) };
        assert_eq!(len, 5);
    }

    #[test]
    fn test_lstrcpy_w() {
        let src: Vec<u16> = "hello\0".encode_utf16().collect();
        let mut dst = vec![0u16; 16];
        let result = unsafe { kernel32_lstrcpyW(dst.as_mut_ptr(), src.as_ptr()) };
        assert!(!result.is_null());
        let copied: String = dst
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert_eq!(copied, "hello");
    }

    #[test]
    fn test_lstrcmpi_w() {
        let s1: Vec<u16> = "Hello\0".encode_utf16().collect();
        let s2: Vec<u16> = "hello\0".encode_utf16().collect();
        let result = unsafe { kernel32_lstrcmpiW(s1.as_ptr(), s2.as_ptr()) };
        assert_eq!(result, 0, "Case-insensitive compare should return 0");
    }

    #[test]
    fn test_output_debug_string_w() {
        let s: Vec<u16> = "test debug\0".encode_utf16().collect();
        unsafe { kernel32_OutputDebugStringW(s.as_ptr()) };
    }

    #[test]
    fn test_get_drive_type() {
        let path: Vec<u16> = "C:\\\0".encode_utf16().collect();
        let t = unsafe { kernel32_GetDriveTypeW(path.as_ptr()) };
        assert_eq!(t, 3, "Should return DRIVE_FIXED");
    }

    #[test]
    fn test_get_logical_drives() {
        let result = unsafe { kernel32_GetLogicalDrives() };
        assert_eq!(result, 0x4);
    }

    #[test]
    fn test_get_disk_free_space() {
        let mut free: u64 = 0;
        let mut total: u64 = 0;
        let r = unsafe {
            kernel32_GetDiskFreeSpaceExW(
                core::ptr::null(),
                core::ptr::addr_of_mut!(free),
                core::ptr::addr_of_mut!(total),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, 1);
        assert!(free > 0);
        assert!(total > 0);
    }

    #[test]
    fn test_get_computer_name() {
        let mut buf = vec![0u16; 256];
        let mut size: u32 = 256;
        let r =
            unsafe { kernel32_GetComputerNameW(buf.as_mut_ptr(), core::ptr::addr_of_mut!(size)) };
        assert_eq!(r, 1);
        assert!(size > 0);
        let name: String = buf[..size as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert!(!name.is_empty());
    }

    // ── Phase 27 tests ────────────────────────────────────────────────────
    #[test]
    fn test_set_get_thread_priority() {
        let result = unsafe { kernel32_SetThreadPriority(core::ptr::null_mut(), 0) };
        assert_eq!(result, 1);
        let priority = unsafe { kernel32_GetThreadPriority(core::ptr::null_mut()) };
        assert_eq!(priority, 0); // THREAD_PRIORITY_NORMAL
    }

    #[test]
    fn test_suspend_resume_thread() {
        let prev_count = unsafe { kernel32_SuspendThread(core::ptr::null_mut()) };
        assert_eq!(prev_count, 0);
        let prev_count2 = unsafe { kernel32_ResumeThread(core::ptr::null_mut()) };
        assert_eq!(prev_count2, 0);
    }

    #[test]
    fn test_open_process_current() {
        let pid = unsafe { kernel32_GetCurrentProcessId() };
        let handle = unsafe { kernel32_OpenProcess(0x1F0FFF, 0, pid) };
        assert!(
            !handle.is_null(),
            "OpenProcess for current pid should succeed"
        );
    }

    #[test]
    fn test_open_process_unknown() {
        let handle = unsafe { kernel32_OpenProcess(0x1F0FFF, 0, 0xDEAD) };
        assert!(handle.is_null(), "OpenProcess for unknown pid should fail");
    }

    #[test]
    fn test_get_process_times() {
        let mut creation = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut exit = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut kernel = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let mut user = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let r = unsafe {
            kernel32_GetProcessTimes(
                usize::MAX as *mut _,
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        assert_eq!(r, 1);
        let creation_val =
            u64::from(creation.low_date_time) | (u64::from(creation.high_date_time) << 32);
        assert!(creation_val > 0, "creation time should be non-zero");
    }

    #[test]
    fn test_get_file_time() {
        use std::io::Write as _;
        let dir = std::env::temp_dir();
        let path = dir.join("kernel32_get_file_time_test.tmp");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello").unwrap();
        }
        let wide: Vec<u16> = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(core::iter::once(0))
            .collect();
        let h = unsafe {
            kernel32_CreateFileW(
                wide.as_ptr(),
                0x8000_0000u32, // GENERIC_READ
                1,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h.is_null());
        assert_ne!(h as usize, usize::MAX);
        let mut write_time = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let r = unsafe {
            kernel32_GetFileTime(
                h,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &raw mut write_time,
            )
        };
        assert_eq!(r, 1, "GetFileTime should succeed");
        let wt_val =
            u64::from(write_time.low_date_time) | (u64::from(write_time.high_date_time) << 32);
        assert!(wt_val > 0, "write time should be non-zero");
        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_compare_file_time() {
        let earlier = FileTime {
            low_date_time: 100,
            high_date_time: 0,
        };
        let later = FileTime {
            low_date_time: 200,
            high_date_time: 0,
        };
        let same = FileTime {
            low_date_time: 100,
            high_date_time: 0,
        };
        assert_eq!(
            unsafe { kernel32_CompareFileTime(&raw const earlier, &raw const later) },
            -1
        );
        assert_eq!(
            unsafe { kernel32_CompareFileTime(&raw const later, &raw const earlier) },
            1
        );
        assert_eq!(
            unsafe { kernel32_CompareFileTime(&raw const earlier, &raw const same) },
            0
        );
    }

    #[test]
    fn test_file_time_to_local() {
        let utc = FileTime {
            low_date_time: 0xD53E_8000,
            high_date_time: 0x01D9_E2A4,
        };
        let mut local = FileTime {
            low_date_time: 0,
            high_date_time: 0,
        };
        let r = unsafe { kernel32_FileTimeToLocalFileTime(&raw const utc, &raw mut local) };
        assert_eq!(r, 1);
        let local_val = u64::from(local.low_date_time) | (u64::from(local.high_date_time) << 32);
        assert!(local_val > 0);
    }

    #[test]
    fn test_get_system_directory() {
        let mut buf = vec![0u16; 260];
        let result = unsafe { kernel32_GetSystemDirectoryW(buf.as_mut_ptr(), 260) };
        assert!(result > 0);
        let s: String = buf[..result as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert!(
            s.contains("System32") || s.contains("system32"),
            "Should contain System32, got: {s}"
        );
    }

    #[test]
    fn test_get_windows_directory() {
        let mut buf = vec![0u16; 260];
        let result = unsafe { kernel32_GetWindowsDirectoryW(buf.as_mut_ptr(), 260) };
        assert!(result > 0);
        let s: String = buf[..result as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert!(s.contains("Windows"), "Should contain Windows, got: {s}");
    }

    #[test]
    fn test_get_temp_file_name() {
        let path: Vec<u16> = "C:\\Temp\0".encode_utf16().collect();
        let prefix: Vec<u16> = "tmp\0".encode_utf16().collect();
        let mut out = vec![0u16; 260];
        let result = unsafe {
            kernel32_GetTempFileNameW(path.as_ptr(), prefix.as_ptr(), 0x1234, out.as_mut_ptr())
        };
        assert!(result > 0);
        let s: String = out[..result as usize]
            .iter()
            .map(|&c| char::from_u32(u32::from(c)).unwrap_or('?'))
            .collect();
        assert!(s.contains("tmp"), "Should contain prefix, got: {s}");
        assert!(
            std::path::Path::new(&s)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp")),
            "Should end with .tmp, got: {s}"
        );
    }

    #[test]
    fn test_get_file_size() {
        let path = std::env::temp_dir().join("test_get_file_size.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let path_wide: Vec<u16> = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let h = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h.is_null());
        let mut high: u32 = 0xDEAD;
        let low = unsafe { kernel32_GetFileSize(h, &raw mut high) };
        assert_eq!(low, 11);
        assert_eq!(high, 0);
        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_get_set_file_pointer() {
        let path = std::env::temp_dir().join("test_set_file_pointer.bin");
        std::fs::write(&path, b"0123456789").unwrap();
        let path_wide: Vec<u16> = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let h = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0xC000_0000, // GENERIC_READ|GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h.is_null());
        let pos = unsafe { kernel32_SetFilePointer(h, 5, core::ptr::null_mut(), 0) };
        assert_eq!(pos, 5);
        unsafe { kernel32_CloseHandle(h) };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_set_end_of_file() {
        let path = std::env::temp_dir().join("test_set_end_of_file.bin");
        std::fs::write(&path, b"hello world").unwrap();
        let path_wide: Vec<u16> = path
            .to_str()
            .unwrap()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let h = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0xC000_0000,
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert!(!h.is_null());
        unsafe { kernel32_SetFilePointer(h, 5, core::ptr::null_mut(), 0) };
        let r = unsafe { kernel32_SetEndOfFile(h) };
        assert_eq!(r, 1);
        unsafe { kernel32_CloseHandle(h) };
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content.len(), 5);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_lang_lcid() {
        unsafe {
            assert_eq!(kernel32_GetSystemDefaultLangID(), 0x0409);
            assert_eq!(kernel32_GetUserDefaultLangID(), 0x0409);
            assert_eq!(kernel32_GetSystemDefaultLCID(), 0x0409);
            assert_eq!(kernel32_GetUserDefaultLCID(), 0x0409);
        }
    }

    #[test]
    fn test_flush_view_of_file_null() {
        // Null pointer should return FALSE (0)
        let result = unsafe { kernel32_FlushViewOfFile(core::ptr::null(), 0) };
        assert_eq!(result, 0, "FlushViewOfFile(null) should return 0");
    }

    #[test]
    fn test_flush_view_of_file_mapped() {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let len = page_size.max(4096);

        let dir = std::env::temp_dir();
        let path = dir.join("kernel32_flush_view_test.tmp");

        // Create file and write initial contents
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(&vec![b'A'; len]).unwrap();
        }

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let fd = file.as_raw_fd();
        let mapped = unsafe {
            // SAFETY: fd is valid, len > 0, offset is 0 (page-aligned)
            libc::mmap(
                core::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED, "mmap failed");

        // Modify through the mapping
        unsafe {
            // SAFETY: mapped is valid for len bytes
            *mapped.cast::<u8>() = b'B';
        }

        // Flush using our kernel32 wrapper
        let result = unsafe { kernel32_FlushViewOfFile(mapped.cast(), len) };
        assert_eq!(result, 1, "FlushViewOfFile should return 1 (success)");

        // Verify the change persisted
        let content = std::fs::read(&path).unwrap();
        assert_eq!(content[0], b'B', "mapped write should be visible in file");

        unsafe {
            // SAFETY: mapped/len match mmap arguments
            libc::munmap(mapped, len);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_rtl_pc_to_file_header_out_of_range() {
        // A PC far outside any registered image should return null.
        let mut base: *mut core::ffi::c_void = core::ptr::without_provenance_mut(1); // sentinel
        let result = unsafe {
            kernel32_RtlPcToFileHeader(core::ptr::without_provenance_mut(usize::MAX), &raw mut base)
        };
        assert!(result.is_null());
        assert!(base.is_null());
    }

    // ── IOCP and async I/O tests ───────────────────────────────────────────

    /// PostQueuedCompletionStatus / GetQueuedCompletionStatus round-trip.
    #[test]
    fn test_iocp_post_and_dequeue() {
        // Create a new IOCP.
        let port = unsafe {
            kernel32_CreateIoCompletionPort(
                (-1isize) as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                0,
            )
        };
        assert!(
            !port.is_null(),
            "CreateIoCompletionPort should return a valid handle"
        );

        // Post a completion packet.
        let res =
            unsafe { kernel32_PostQueuedCompletionStatus(port, 42, 0x1234, core::ptr::null_mut()) };
        assert_eq!(res, 1, "PostQueuedCompletionStatus should return TRUE");

        // Dequeue it immediately (non-blocking via milliseconds=0).
        let mut bytes: u32 = 0;
        let mut key: usize = 0;
        let mut ov: *mut core::ffi::c_void = core::ptr::null_mut();
        let res = unsafe {
            kernel32_GetQueuedCompletionStatus(port, &raw mut bytes, &raw mut key, &raw mut ov, 0)
        };
        assert_eq!(res, 1, "GetQueuedCompletionStatus should return TRUE");
        assert_eq!(bytes, 42);
        assert_eq!(key, 0x1234);
        assert!(ov.is_null());

        // Close the port.
        unsafe { kernel32_CloseHandle(port) };
    }

    /// GetQueuedCompletionStatus times out when the queue is empty.
    #[test]
    fn test_iocp_timeout() {
        let port = unsafe {
            kernel32_CreateIoCompletionPort(
                (-1isize) as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                0,
            )
        };
        assert!(!port.is_null());

        let mut bytes: u32 = u32::MAX;
        let mut key: usize = usize::MAX;
        let mut ov: *mut core::ffi::c_void = core::ptr::without_provenance_mut(1);
        // Non-blocking: should return FALSE immediately.
        let res = unsafe {
            kernel32_GetQueuedCompletionStatus(port, &raw mut bytes, &raw mut key, &raw mut ov, 0)
        };
        assert_eq!(res, 0, "Should time out immediately");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 258, "Last error should be WAIT_TIMEOUT (258)");

        unsafe { kernel32_CloseHandle(port) };
    }

    /// ReadFileEx enqueues an APC; SleepEx with alertable=TRUE drains it.
    #[test]
    fn test_read_file_ex_apc() {
        use std::io::Write as _;

        // Static callback that stores the byte count.
        static CALLBACK_BYTES: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(u32::MAX);

        unsafe extern "win64" fn my_callback(_err: u32, bytes: u32, _ov: *mut core::ffi::c_void) {
            CALLBACK_BYTES.store(bytes, std::sync::atomic::Ordering::SeqCst);
        }

        // Create a temporary file and write some data.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("litebox_rfex_test_{}.tmp", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"hello async").unwrap();
        }

        // Open the file.
        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000u32, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(handle as usize, usize::MAX, "CreateFileW should succeed");

        // Prepare OVERLAPPED and buffer.
        let mut ov = [0u8; 32];
        let mut buf = [0u8; 16];

        // Issue the async read.
        let res = unsafe {
            kernel32_ReadFileEx(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                ov.as_mut_ptr().cast(),
                my_callback as *mut core::ffi::c_void,
            )
        };
        assert_eq!(res, 1, "ReadFileEx should return TRUE");

        // APC has not fired yet.
        assert_eq!(
            CALLBACK_BYTES.load(std::sync::atomic::Ordering::SeqCst),
            u32::MAX,
            "APC should not have fired before alertable wait"
        );

        // SleepEx with alertable=TRUE should drain the APC queue.
        let sleep_res = unsafe { kernel32_SleepEx(0, 1) };
        assert_eq!(sleep_res, 0xC0, "SleepEx should return WAIT_IO_COMPLETION");

        // Callback should have been invoked.
        let cb_bytes = CALLBACK_BYTES.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(cb_bytes, b"hello async".len() as u32);

        // Verify GetOverlappedResult.
        let mut transferred: u32 = 0;
        let gor = unsafe {
            kernel32_GetOverlappedResult(handle, ov.as_mut_ptr().cast(), &raw mut transferred, 0)
        };
        assert_eq!(gor, 1, "GetOverlappedResult should return TRUE");
        assert_eq!(transferred, b"hello async".len() as u32);

        unsafe { kernel32_CloseHandle(handle) };
        let _ = std::fs::remove_file(&path);
    }

    /// WriteFileEx enqueues an APC; WaitForSingleObjectEx with alertable=TRUE drains it.
    #[test]
    fn test_write_file_ex_apc() {
        static WFX_CALLBACK_BYTES: std::sync::atomic::AtomicU32 =
            std::sync::atomic::AtomicU32::new(u32::MAX);

        unsafe extern "win64" fn wfx_callback(_err: u32, bytes: u32, _ov: *mut core::ffi::c_void) {
            WFX_CALLBACK_BYTES.store(bytes, std::sync::atomic::Ordering::SeqCst);
        }

        let dir = std::env::temp_dir();
        let path = dir.join(format!("litebox_wfex_test_{}.tmp", std::process::id()));

        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x4000_0000u32, // GENERIC_WRITE
                0,
                core::ptr::null_mut(),
                2, // CREATE_ALWAYS
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(handle as usize, usize::MAX, "CreateFileW should succeed");

        let mut ov = [0u8; 32];
        let data = b"write async";

        let res = unsafe {
            kernel32_WriteFileEx(
                handle,
                data.as_ptr(),
                data.len() as u32,
                ov.as_mut_ptr().cast(),
                wfx_callback as *mut core::ffi::c_void,
            )
        };
        assert_eq!(res, 1, "WriteFileEx should return TRUE");

        // APC not fired yet.
        assert_eq!(
            WFX_CALLBACK_BYTES.load(std::sync::atomic::Ordering::SeqCst),
            u32::MAX
        );

        // Use WaitForSingleObjectEx with alertable=TRUE to drain APCs.
        let wait_res = unsafe {
            kernel32_WaitForSingleObjectEx(
                core::ptr::null_mut(),
                0,
                1, // alertable
            )
        };
        assert_eq!(
            wait_res, 0xC0,
            "WaitForSingleObjectEx should return WAIT_IO_COMPLETION"
        );
        assert_eq!(
            WFX_CALLBACK_BYTES.load(std::sync::atomic::Ordering::SeqCst),
            data.len() as u32
        );

        unsafe { kernel32_CloseHandle(handle) };
        let _ = std::fs::remove_file(&path);
    }

    /// IOCP-associated ReadFile posts a completion packet.
    #[test]
    fn test_iocp_associated_read_file() {
        use std::io::Write as _;

        let dir = std::env::temp_dir();
        let path = dir.join(format!("litebox_iocp_rf_test_{}.tmp", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"iocp read").unwrap();
        }

        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let handle = unsafe {
            kernel32_CreateFileW(
                path_wide.as_ptr(),
                0x8000_0000u32, // GENERIC_READ
                0,
                core::ptr::null_mut(),
                3, // OPEN_EXISTING
                0,
                core::ptr::null_mut(),
            )
        };
        assert_ne!(handle as usize, usize::MAX);

        // Create IOCP and associate the file.
        let port = unsafe {
            kernel32_CreateIoCompletionPort(
                (-1isize) as *mut core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                0,
            )
        };
        assert!(!port.is_null());

        let assoc = unsafe { kernel32_CreateIoCompletionPort(handle, port, 0xDEAD, 0) };
        assert_eq!(
            assoc, port,
            "Association should return the same port handle"
        );

        // ReadFile with non-null OVERLAPPED should post a completion.
        let mut ov = [0u8; 32];
        let mut buf = [0u8; 16];
        let mut bytes_read: u32 = 0;
        let res = unsafe {
            kernel32_ReadFile(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut bytes_read,
                ov.as_mut_ptr().cast(),
            )
        };
        assert_eq!(res, 1, "ReadFile should succeed");

        // Dequeue the completion.
        let mut comp_bytes: u32 = 0;
        let mut comp_key: usize = 0;
        let mut comp_ov: *mut core::ffi::c_void = core::ptr::null_mut();
        let deq = unsafe {
            kernel32_GetQueuedCompletionStatus(
                port,
                &raw mut comp_bytes,
                &raw mut comp_key,
                &raw mut comp_ov,
                0,
            )
        };
        assert_eq!(deq, 1, "Should dequeue the ReadFile completion");
        assert_eq!(comp_key, 0xDEAD);
        assert_eq!(comp_bytes, b"iocp read".len() as u32);

        unsafe { kernel32_CloseHandle(handle) };
        unsafe { kernel32_CloseHandle(port) };
        let _ = std::fs::remove_file(&path);
    }

    // ── Phase 39 tests ────────────────────────────────────────────────────

    #[test]
    fn test_get_priority_class_current_process() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let cls = unsafe { kernel32_GetPriorityClass(handle) };
        assert_eq!(cls, NORMAL_PRIORITY_CLASS, "expected NORMAL_PRIORITY_CLASS");
    }

    #[test]
    fn test_get_priority_class_null_handle() {
        let cls = unsafe { kernel32_GetPriorityClass(core::ptr::null_mut()) };
        assert_eq!(cls, 0, "null handle should return 0");
    }

    #[test]
    fn test_set_priority_class_current_process() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_SetPriorityClass(handle, NORMAL_PRIORITY_CLASS) };
        assert_eq!(result, 1, "SetPriorityClass should return TRUE");
    }

    #[test]
    fn test_set_priority_class_null_handle() {
        let result =
            unsafe { kernel32_SetPriorityClass(core::ptr::null_mut(), NORMAL_PRIORITY_CLASS) };
        assert_eq!(result, 0, "null handle should return FALSE");
    }

    #[test]
    fn test_get_process_affinity_mask() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let mut proc_mask: usize = 0;
        let mut sys_mask: usize = 0;
        let result = unsafe {
            kernel32_GetProcessAffinityMask(handle, &raw mut proc_mask, &raw mut sys_mask)
        };
        assert_eq!(result, 1, "GetProcessAffinityMask should return TRUE");
        assert_ne!(proc_mask, 0, "process affinity mask should be non-zero");
        assert_eq!(proc_mask, sys_mask, "process and system masks should match");
    }

    #[test]
    fn test_set_process_affinity_mask() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_SetProcessAffinityMask(handle, 0x1) };
        assert_eq!(result, 1, "SetProcessAffinityMask should return TRUE");
    }

    #[test]
    fn test_flush_instruction_cache() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_FlushInstructionCache(handle, core::ptr::null(), 0) };
        assert_eq!(result, 1, "FlushInstructionCache should return TRUE");
    }

    #[test]
    fn test_read_write_process_memory() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let src: u64 = 0xDEAD_BEEF_CAFE_1234;
        let mut dst: u64 = 0;
        let mut n: usize = 0;
        let result = unsafe {
            kernel32_ReadProcessMemory(
                handle,
                (&raw const src).cast::<core::ffi::c_void>(),
                (&raw mut dst).cast::<core::ffi::c_void>(),
                8,
                &raw mut n,
            )
        };
        assert_eq!(result, 1, "ReadProcessMemory should return TRUE");
        assert_eq!(n, 8);
        assert_eq!(dst, src);

        let val: u64 = 0x1122_3344_5566_7788;
        let mut out: u64 = 0;
        let mut written: usize = 0;
        let result2 = unsafe {
            kernel32_WriteProcessMemory(
                handle,
                (&raw mut out).cast::<core::ffi::c_void>(),
                (&raw const val).cast::<core::ffi::c_void>(),
                8,
                &raw mut written,
            )
        };
        assert_eq!(result2, 1, "WriteProcessMemory should return TRUE");
        assert_eq!(written, 8);
        assert_eq!(out, val);
    }

    #[test]
    fn test_virtual_alloc_free_ex() {
        let handle = unsafe { kernel32_GetCurrentProcess() };
        let ptr = unsafe {
            kernel32_VirtualAllocEx(
                handle,
                core::ptr::null_mut(),
                4096,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            )
        };
        assert!(!ptr.is_null(), "VirtualAllocEx should return non-null");
        let result = unsafe { kernel32_VirtualFreeEx(handle, ptr, 0, 0x8000) }; // MEM_RELEASE
        assert_eq!(result, 1, "VirtualFreeEx should return TRUE");
    }

    #[test]
    fn test_virtual_alloc_ex_wrong_process() {
        let ptr = unsafe {
            kernel32_VirtualAllocEx(
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                4096,
                0x3000,
                0x04,
            )
        };
        assert!(ptr.is_null(), "VirtualAllocEx with null handle should fail");
    }

    #[test]
    fn test_create_job_object_w() {
        let handle = unsafe { kernel32_CreateJobObjectW(core::ptr::null_mut(), core::ptr::null()) };
        assert!(!handle.is_null(), "CreateJobObjectW should return non-null");
        assert_eq!(handle as usize, JOB_OBJECT_HANDLE);
    }

    #[test]
    fn test_assign_process_to_job_object() {
        let job = unsafe { kernel32_CreateJobObjectW(core::ptr::null_mut(), core::ptr::null()) };
        let proc_handle = unsafe { kernel32_GetCurrentProcess() };
        let result = unsafe { kernel32_AssignProcessToJobObject(job, proc_handle) };
        assert_eq!(result, 1, "AssignProcessToJobObject should return TRUE");
    }

    #[test]
    fn test_is_process_in_job() {
        let proc_handle = unsafe { kernel32_GetCurrentProcess() };
        let mut in_job: i32 = 1;
        let result =
            unsafe { kernel32_IsProcessInJob(proc_handle, core::ptr::null_mut(), &raw mut in_job) };
        assert_eq!(result, 1, "IsProcessInJob should return TRUE");
        assert_eq!(in_job, 0, "process should not be in a job");
    }

    #[test]
    fn test_query_information_job_object() {
        let job = unsafe { kernel32_CreateJobObjectW(core::ptr::null_mut(), core::ptr::null()) };
        let mut buf = [0u8; 144];
        let mut ret_len: u32 = 0;
        let result = unsafe {
            kernel32_QueryInformationJobObject(
                job,
                9, // JobObjectExtendedLimitInformation
                buf.as_mut_ptr().cast::<core::ffi::c_void>(),
                buf.len() as u32,
                &raw mut ret_len,
            )
        };
        assert_eq!(result, 1, "QueryInformationJobObject should return TRUE");
        assert_eq!(ret_len, 144);
    }

    #[test]
    fn test_set_information_job_object() {
        let job = unsafe { kernel32_CreateJobObjectW(core::ptr::null_mut(), core::ptr::null()) };
        let result = unsafe {
            kernel32_SetInformationJobObject(
                job,
                9, // JobObjectExtendedLimitInformation
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(result, 1, "SetInformationJobObject should return TRUE");
    }

    #[test]
    fn test_open_job_object_w_unsupported() {
        let handle = unsafe { kernel32_OpenJobObjectW(0x1F003F, 0, core::ptr::null()) };
        assert!(
            handle.is_null(),
            "OpenJobObjectW should return NULL (not supported)"
        );
    }

    // ── CreateProcessW / CreateProcessA tests ─────────────────────────────

    /// Verify the command-line parser handles basic unquoted tokens.
    #[test]
    fn test_parse_command_line_basic() {
        let args = parse_command_line_str("foo bar baz");
        assert_eq!(args, vec!["foo", "bar", "baz"]);
    }

    /// Verify the command-line parser handles quoted tokens with spaces.
    #[test]
    fn test_parse_command_line_quoted() {
        let args = parse_command_line_str("\"hello world\" foo");
        assert_eq!(args, vec!["hello world", "foo"]);
    }

    /// Verify backslash-escaping rules before a double quote.
    #[test]
    fn test_parse_command_line_backslash_escape() {
        // Two backslashes NOT followed by a quote are literal.
        // Input: "\\" (opening quote, two backslashes) → token is \\ (two backslashes).
        let args = parse_command_line_str(r#""\\"#);
        assert_eq!(
            args,
            vec!["\\\\"],
            "two literal backslashes inside quotes should produce two backslashes"
        );
        // Two backslashes followed by a closing quote → one literal backslash, end of quote.
        // Input: "\\"" (opening quote, two backslashes, closing quote) → token is \.
        let args2 = parse_command_line_str("\"\\\\\"");
        assert_eq!(
            args2,
            vec!["\\"],
            "paired backslashes before closing quote should collapse to one backslash"
        );
    }

    /// CreateProcessW with a null application_name and null command_line returns FALSE.
    #[test]
    fn test_create_process_w_no_args() {
        let result = unsafe {
            kernel32_CreateProcessW(
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "CreateProcessW with no args should return FALSE");
        let err = unsafe { kernel32_GetLastError() };
        assert_eq!(err, 87, "should set ERROR_INVALID_PARAMETER (87)");
    }

    /// CreateProcessW spawning a native Linux binary (`/bin/true`) succeeds and
    /// WaitForSingleObject / GetExitCodeProcess work correctly.
    #[test]
    fn test_create_process_w_native_binary() {
        use crate::kernel32::{
            kernel32_CloseHandle, kernel32_CreateProcessW, kernel32_GetExitCodeProcess,
            kernel32_WaitForSingleObject,
        };
        #[repr(C)]
        struct ProcInfo {
            h_process: usize,
            h_thread: usize,
            dw_pid: u32,
            dw_tid: u32,
        }
        // Encode "/bin/true" as null-terminated UTF-16
        let exe_wide: Vec<u16> = "/bin/true\0".encode_utf16().collect();

        let mut pi = ProcInfo {
            h_process: 0,
            h_thread: 0,
            dw_pid: 0,
            dw_tid: 0,
        };

        let result = unsafe {
            kernel32_CreateProcessW(
                exe_wide.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                (&raw mut pi).cast::<core::ffi::c_void>(),
            )
        };
        assert_eq!(result, 1, "CreateProcessW should return TRUE for /bin/true");
        assert_ne!(pi.h_process, 0, "hProcess should be non-zero");
        assert_ne!(pi.dw_pid, 0, "dwProcessId should be non-zero");

        // Wait for the child to exit (infinite wait)
        let wait_result = unsafe {
            kernel32_WaitForSingleObject(pi.h_process as *mut core::ffi::c_void, u32::MAX)
        };
        assert_eq!(wait_result, 0, "WAIT_OBJECT_0 expected");

        // GetExitCodeProcess should return TRUE and the real exit code (0 for /bin/true)
        let mut exit_code: u32 = 999;
        let gecp_result = unsafe {
            kernel32_GetExitCodeProcess(pi.h_process as *mut core::ffi::c_void, &raw mut exit_code)
        };
        assert_eq!(gecp_result, 1, "GetExitCodeProcess should return TRUE");
        assert_eq!(exit_code, 0, "/bin/true should exit with code 0");

        // CloseHandle on process and thread handles should succeed
        let r1 = unsafe { kernel32_CloseHandle(pi.h_process as *mut core::ffi::c_void) };
        let r2 = unsafe { kernel32_CloseHandle(pi.h_thread as *mut core::ffi::c_void) };
        assert_eq!(r1, 1);
        assert_eq!(r2, 1);
    }

    /// CreateProcessW spawning a non-existent executable returns FALSE + ERROR_FILE_NOT_FOUND.
    #[test]
    fn test_create_process_w_missing_exe() {
        let exe_wide: Vec<u16> = "/nonexistent/missing_exe_abc123\0".encode_utf16().collect();
        let result = unsafe {
            kernel32_CreateProcessW(
                exe_wide.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(
            result, 0,
            "CreateProcessW should return FALSE for missing exe"
        );
        let err = unsafe { kernel32_GetLastError() };
        // Should be ERROR_FILE_NOT_FOUND (2) or ERROR_ACCESS_DENIED (5)
        assert!(
            err == 2 || err == 5,
            "last error should be file-not-found or access-denied, got {err}"
        );
    }

    /// TerminateProcess can kill a child spawned via CreateProcessW.
    #[test]
    fn test_terminate_process_child() {
        // Use /bin/sleep to start a long-running child we can kill.
        #[repr(C)]
        struct ProcInfo {
            h_process: usize,
            h_thread: usize,
            dw_pid: u32,
            dw_tid: u32,
        }
        let exe_wide: Vec<u16> = "/bin/sleep\0".encode_utf16().collect();
        let arg_wide: Vec<u16> = "/bin/sleep 60\0".encode_utf16().collect();

        let mut pi = ProcInfo {
            h_process: 0,
            h_thread: 0,
            dw_pid: 0,
            dw_tid: 0,
        };

        let result = unsafe {
            kernel32_CreateProcessW(
                exe_wide.as_ptr(),
                arg_wide.as_ptr().cast_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                (&raw mut pi).cast::<core::ffi::c_void>(),
            )
        };
        assert_eq!(result, 1, "CreateProcessW(/bin/sleep 60) should succeed");
        assert_ne!(pi.h_process, 0);

        // Terminate the child.
        let term_result =
            unsafe { kernel32_TerminateProcess(pi.h_process as *mut core::ffi::c_void, 42) };
        assert_eq!(term_result, 1, "TerminateProcess should return TRUE");

        // Clean up handles.
        unsafe {
            kernel32_CloseHandle(pi.h_process as *mut core::ffi::c_void);
            kernel32_CloseHandle(pi.h_thread as *mut core::ffi::c_void);
        }
    }

    /// OpenProcess by PID of a known child returns the same handle that was
    /// allocated by CreateProcessW.
    #[test]
    fn test_open_process_known_child() {
        #[repr(C)]
        struct ProcInfo {
            h_process: usize,
            h_thread: usize,
            dw_pid: u32,
            dw_tid: u32,
        }
        let exe_wide: Vec<u16> = "/bin/true\0".encode_utf16().collect();

        let mut pi = ProcInfo {
            h_process: 0,
            h_thread: 0,
            dw_pid: 0,
            dw_tid: 0,
        };

        let result = unsafe {
            kernel32_CreateProcessW(
                exe_wide.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                0,
                0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                (&raw mut pi).cast::<core::ffi::c_void>(),
            )
        };
        assert_eq!(result, 1, "CreateProcessW should succeed");

        // OpenProcess by the real PID should return the same synthetic handle.
        let opened = unsafe { kernel32_OpenProcess(0x0010, 0, pi.dw_pid) } as usize;
        assert_eq!(
            opened, pi.h_process,
            "OpenProcess should return the same handle as CreateProcessW"
        );

        // Wait and clean up.
        unsafe {
            kernel32_WaitForSingleObject(pi.h_process as *mut core::ffi::c_void, u32::MAX);
            kernel32_CloseHandle(pi.h_process as *mut core::ffi::c_void);
            kernel32_CloseHandle(pi.h_thread as *mut core::ffi::c_void);
        }
    }

    // ── Phase 43: Volume enumeration tests ───────────────────────────────────

    #[test]
    fn test_find_first_volume_returns_handle_and_path() {
        let mut name = [0u16; 64];
        let handle = unsafe { kernel32_FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
        assert_ne!(
            handle as usize,
            usize::MAX,
            "FindFirstVolumeW should not return INVALID_HANDLE_VALUE"
        );
        assert_ne!(handle, core::ptr::null_mut(), "Handle should be non-null");
        // Verify the returned path starts with the expected prefix.
        let nul = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        let path = String::from_utf16_lossy(&name[..nul]);
        assert!(
            path.starts_with("\\\\?\\Volume{"),
            "Volume path should start with '\\\\?\\Volume{{'  got: {path}"
        );
        unsafe { kernel32_FindVolumeClose(handle) };
    }

    #[test]
    fn test_find_next_volume_returns_no_more_files() {
        let mut name = [0u16; 64];
        let handle = unsafe { kernel32_FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
        assert_ne!(handle as usize, usize::MAX);
        let ret = unsafe { kernel32_FindNextVolumeW(handle, name.as_mut_ptr(), name.len() as u32) };
        assert_eq!(ret, 0, "FindNextVolumeW should return 0 (no more volumes)");
        unsafe { kernel32_FindVolumeClose(handle) };
    }

    #[test]
    fn test_find_volume_close_returns_success() {
        let mut name = [0u16; 64];
        let handle = unsafe { kernel32_FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32) };
        assert_ne!(handle as usize, usize::MAX);
        let ret = unsafe { kernel32_FindVolumeClose(handle) };
        assert_eq!(ret, 1, "FindVolumeClose should return 1");
    }

    #[test]
    fn test_get_volume_path_names_returns_backslash() {
        let mut buf = [0u16; 8];
        let mut ret_len: u32 = 0;
        let result = unsafe {
            kernel32_GetVolumePathNamesForVolumeNameW(
                core::ptr::null(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut ret_len,
            )
        };
        assert_eq!(
            result, 1,
            "GetVolumePathNamesForVolumeNameW should return 1"
        );
        assert_eq!(ret_len, 3, "ret_len should be 3 (backslash + 2 NULs)");
        assert_eq!(buf[0], 0x005c, "first char should be backslash");
        assert_eq!(buf[1], 0, "second char should be NUL");
        assert_eq!(buf[2], 0, "third char should be NUL");
    }

    #[test]
    fn test_get_volume_path_names_buffer_too_small_returns_zero() {
        let mut buf = [0u16; 2]; // too small: needs 3
        let mut ret_len: u32 = 0;
        let result = unsafe {
            kernel32_GetVolumePathNamesForVolumeNameW(
                core::ptr::null(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &raw mut ret_len,
            )
        };
        assert_eq!(result, 0, "should return 0 when buffer is too small");
        assert_eq!(ret_len, 3, "ret_len should still indicate required size");
    }
}
