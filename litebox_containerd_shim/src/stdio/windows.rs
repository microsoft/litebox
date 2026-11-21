// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Overlapped output lets deletion cancel a write that containerd has not read.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::WRITE_POLL;

/// go-winio reserves the first instance; containerd's asynchronous `Accept` opens the next.
const PIPE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// As go-winio's own dialer.
const PIPE_BUSY_POLL: Duration = Duration::from_millis(10);

pub fn open_pipe(options: &OpenOptions, path: &Path) -> io::Result<File> {
    let deadline = Instant::now() + PIPE_BUSY_TIMEOUT;
    loop {
        match options.open(path) {
            Err(error)
                if error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok()
                    && Instant::now() < deadline =>
            {
                std::thread::sleep(PIPE_BUSY_POLL);
            }
            opened => return opened,
        }
    }
}

/// Not a [`File`]: std aborts the process when a synchronous write on an overlapped handle pends.
pub struct Output {
    handle: OwnedHandle,
    event: OwnedHandle,
}

impl Output {
    /// `file` must be open for overlapped I/O.
    pub fn new(file: File) -> io::Result<Self> {
        // SAFETY: manual-reset, unsignalled, with neither attributes nor a name.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        if event.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call succeeded, so this owns `event`.
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        Ok(Self {
            handle: file.into(),
            event,
        })
    }

    /// A pending write is cancelled on deletion, not on a deadline.
    pub fn write_all(&self, mut data: &[u8], deleted: &AtomicBool) -> io::Result<()> {
        while !data.is_empty() {
            match self.write(data, deleted)? {
                0 => return Err(io::ErrorKind::WriteZero.into()),
                written => data = &data[written..],
            }
        }
        Ok(())
    }

    fn write(&self, data: &[u8], deleted: &AtomicBool) -> io::Result<usize> {
        let handle = self.handle.as_raw_handle();
        let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
        // An appending write's offset; a pipe ignores it.
        let at_end = OVERLAPPED_0_0 {
            Offset: u32::MAX,
            OffsetHigh: u32::MAX,
        };
        let mut overlapped = OVERLAPPED {
            Anonymous: OVERLAPPED_0 { Anonymous: at_end },
            hEvent: self.event.as_raw_handle(),
            ..OVERLAPPED::default()
        };
        // SAFETY: `data` and `overlapped` outlive the write: it does not start, or it is waited
        // for below, cancelled or not.
        let started = unsafe {
            WriteFile(
                handle,
                data.as_ptr(),
                length,
                null_mut(),
                &raw mut overlapped,
            )
        };
        if started == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != i32::try_from(ERROR_IO_PENDING).ok() {
                return Err(error);
            }
            let timeout = u32::try_from(WRITE_POLL.as_millis()).expect("the poll fits in a u32");
            loop {
                // SAFETY: the event is open.
                match unsafe { WaitForSingleObject(self.event.as_raw_handle(), timeout) } {
                    WAIT_OBJECT_0 => break,
                    WAIT_TIMEOUT if !deleted.load(Ordering::SeqCst) => {}
                    _ => {
                        // SAFETY: `overlapped` names a write on `handle`, which is waited for
                        // below.
                        unsafe { CancelIoEx(handle, &raw const overlapped) };
                        break;
                    }
                }
            }
        }
        let mut written = 0;
        // SAFETY: `overlapped` names a write on `handle` that started. Waiting, this returns once
        // the write ended, so that `data` and `overlapped` may then be released.
        if unsafe { GetOverlappedResult(handle, &raw const overlapped, &raw mut written, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(written as usize)
    }
}
