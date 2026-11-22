// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Overlapped output lets deletion cancel a write that containerd has not read.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_IO_PENDING, ERROR_PIPE_BUSY, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION, WriteFile,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, OVERLAPPED, OVERLAPPED_0, OVERLAPPED_0_0,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::{INPUT_POLL, WRITE_POLL};
use crate::{Result, unsupported};

/// go-winio reserves the first instance; containerd's asynchronous `Accept` opens the next.
const PIPE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// As go-winio's own dialer.
const PIPE_BUSY_POLL: Duration = Duration::from_millis(10);

/// Unlike a Unix FIFO, stdin also gets EOF when containerd closes its end.
pub fn open_fifo(path: &Path, input: bool) -> io::Result<File> {
    let mut options = options(input);
    options.read(input).write(!input);
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

pub fn open_file(path: &Path) -> io::Result<File> {
    options(false).append(true).create(true).open(path)
}

pub fn create_dirs(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// No pipe server can impersonate the shim; an output is open for [`Output::new`].
fn options(input: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.security_qos_flags(SECURITY_IDENTIFICATION);
    if !input {
        options.custom_flags(FILE_FLAG_OVERLAPPED);
    }
    options
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

pub fn pending(pipe: &File) -> usize {
    peek(pipe).unwrap_or(0)
}

/// Peek before reading so blocked stdin can still observe `CloseIO`.
pub fn wait_readable(pipe: &File) -> bool {
    if peek(pipe).is_ok_and(|available| available == 0) {
        std::thread::sleep(INPUT_POLL);
        return false;
    }
    true
}

fn peek(pipe: &File) -> io::Result<usize> {
    let mut available = 0;
    // SAFETY: the handle is open for as long as `pipe` is borrowed; with no buffer, only
    // `available` is written, which outlives the call.
    let peeked = unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &raw mut available,
            null_mut(),
        )
    };
    if peeked == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(usize::try_from(available).unwrap_or(usize::MAX))
}

/// Not supported on Windows yet.
pub enum Logger {}

impl Logger {
    pub fn spawn(uri: &str, _id: &str, _namespace: &str) -> Result<(Self, Output, Output)> {
        Err(unsupported(format!(
            "the I/O URI {uri:?}: logging programs are not supported on Windows"
        )))
    }
}
