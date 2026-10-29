// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Out-of-band delivery of host shared objects from the broker to a runner.
//!
//! Some broker responses refer to a host object that the runner must hold itself, such as a
//! section that the runner maps. To deliver one, the broker duplicates its
//! handle into the runner's handle table, then answers the request with the handle's value in
//! the runner as the token the runner takes the object with.

use std::io::{Error, Result as IoResult};
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle, FromRawHandle as _, OwnedHandle};

use windows_sys::Win32::Foundation::DuplicateHandle;
use windows_sys::Win32::System::Memory::{
    SECTION_MAP_EXECUTE, SECTION_MAP_READ, SECTION_MAP_WRITE, SECTION_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, PROCESS_DUP_HANDLE};

use crate::shared_memory::duplicate_handle_to_process;

/// The broker's means of delivering sections to one runner process.
#[derive(Debug)]
pub struct SectionSender {
    process: OwnedHandle,
}

impl SectionSender {
    /// Delivers sections into `process`, which must allow duplicating handles into it.
    pub fn new(process: BorrowedHandle<'_>) -> IoResult<Self> {
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: `process` is a live process handle, and the output is writable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                process.as_raw_handle(),
                GetCurrentProcess(),
                &raw mut duplicate,
                PROCESS_DUP_HANDLE,
                0,
                0,
            )
        } == 0
        {
            return Err(Error::last_os_error());
        }
        // SAFETY: DuplicateHandle returned a new handle that this process owns.
        let process = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        Ok(Self { process })
    }

    /// Moves `section` into the runner, where it may be queried and mapped readable and
    /// executable, and also writable if `writable` is set, returning the token the runner takes
    /// it with.
    ///
    /// The runner gets no right to extend the section, nor to write it unless `writable` is set,
    /// whatever rights `section` has here.
    pub fn send(&self, section: OwnedHandle, writable: bool) -> IoResult<u64> {
        let access = SECTION_QUERY
            | SECTION_MAP_READ
            | SECTION_MAP_EXECUTE
            | if writable { SECTION_MAP_WRITE } else { 0 };
        let delivered = duplicate_handle_to_process(
            section.as_raw_handle(),
            self.process.as_raw_handle(),
            Some(access),
        )?;
        Ok(delivered as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE,
        UnmapViewOfFile,
    };

    #[test]
    fn sent_sections_carry_only_the_requested_rights() {
        // SAFETY: The pseudo-handle names this process and is always valid.
        let sender =
            SectionSender::new(unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) }).unwrap();
        let section = || {
            // SAFETY: Creates a new unnamed pagefile section of one page.
            let section = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    0,
                    4096,
                    std::ptr::null(),
                )
            };
            assert!(!section.is_null(), "{}", Error::last_os_error());
            // SAFETY: CreateFileMappingW returned a new handle that this process owns.
            unsafe { OwnedHandle::from_raw_handle(section) }
        };
        let maps = |token: u64, access| {
            // SAFETY: The token is a section handle that `send` duplicated into this process.
            let section =
                unsafe { OwnedHandle::from_raw_handle(usize::try_from(token).unwrap() as HANDLE) };
            // SAFETY: Maps a fresh view of a live section, unmapped right away.
            let view = unsafe { MapViewOfFile(section.as_raw_handle(), access, 0, 0, 4096) };
            if !view.Value.is_null() {
                // SAFETY: Unmaps the view just mapped.
                unsafe { UnmapViewOfFile(view) };
            }
            !view.Value.is_null()
        };
        let read_only = sender.send(section(), false).unwrap();
        assert!(!maps(read_only, FILE_MAP_READ | FILE_MAP_WRITE));
        let read_only = sender.send(section(), false).unwrap();
        assert!(maps(read_only, FILE_MAP_READ));
        let writable = sender.send(section(), true).unwrap();
        assert!(maps(writable, FILE_MAP_READ | FILE_MAP_WRITE));
    }
}
