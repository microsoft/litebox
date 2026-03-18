// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! NT object handle table.
//!
//! Maps Windows HANDLEs (opaque `usize` values) to typed kernel objects.
//! Handles are allocated as small integers starting from 4 (Windows skips 0,
//! and uses multiples of 4 for compatibility with tagged pointers).

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;

/// The first allocatable handle value. Windows handles start at 4.
const FIRST_HANDLE: u32 = 4;
/// Handle increment (Windows allocates handles in steps of 4).
const HANDLE_STEP: u32 = 4;

/// Shared file position. Duplicated handles share the same host file object
/// and therefore the same file pointer; this `Rc<Cell<u64>>` ensures both
/// handles see the same cached position.
pub type SharedFilePosition = Rc<Cell<u64>>;

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
    /// obtained via DuplicateHandle and the position `Rc` is cloned so both
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
                    position: Rc::clone(position),
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
