// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::time::Instant;

use litebox_broker_protocol::wire::WireError;
use litebox_broker_transport::control_ring::ControlRingError;
use litebox_broker_transport::setup_frame::{SetupFrameError, read_setup_frame, write_setup_frame};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NOT_FOUND, ERROR_PIPE_NOT_CONNECTED,
    HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};

pub(crate) struct OverlappedOperation {
    state: Box<OVERLAPPED>,
    event: OwnedEvent,
}

pub(crate) struct OwnedEvent(HANDLE);

pub(crate) fn read_frame(stream: HANDLE, deadline: Option<Instant>) -> IoResult<Option<Vec<u8>>> {
    read_setup_frame(
        |buffer| read_pipe(stream, buffer, deadline),
        |error| error.kind() == ErrorKind::Interrupted,
    )
    .map_err(frame_error)
}

pub(crate) fn write_frame(stream: HANDLE, frame: &[u8], deadline: Option<Instant>) -> IoResult<()> {
    write_setup_frame(
        frame,
        |buffer| write_pipe(stream, buffer, deadline),
        |error| error.kind() == ErrorKind::Interrupted,
    )
    .map_err(frame_error)
}

fn frame_error(error: SetupFrameError<Error>) -> Error {
    match error {
        SetupFrameError::Io(error) => error,
        SetupFrameError::TruncatedLength => invalid_data("truncated broker frame length"),
        SetupFrameError::InvalidLength => invalid_data("invalid broker frame length"),
        SetupFrameError::TruncatedFrame => invalid_data("truncated broker frame"),
        SetupFrameError::WriteZero => {
            Error::new(ErrorKind::WriteZero, "failed to write broker frame")
        }
        SetupFrameError::InvalidIoCount => Error::other("invalid broker frame I/O count"),
    }
}

pub(crate) fn read_pipe(
    stream: HANDLE,
    buffer: &mut [u8],
    deadline: Option<Instant>,
) -> IoResult<usize> {
    read_pipe_inner(stream, buffer, deadline, None)
}

pub(crate) fn read_pipe_until_cancelled(
    stream: HANDLE,
    buffer: &mut [u8],
    cancellation: HANDLE,
) -> IoResult<usize> {
    read_pipe_inner(stream, buffer, None, Some(cancellation))
}

fn read_pipe_inner(
    stream: HANDLE,
    buffer: &mut [u8],
    deadline: Option<Instant>,
    cancellation: Option<HANDLE>,
) -> IoResult<usize> {
    reject_expired_deadline(deadline)?;
    let length = u32::try_from(buffer.len())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "pipe read buffer is too large"))?;
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: `stream` is an overlapped named-pipe handle, `buffer` remains live until completion,
    // and `operation` owns stable OVERLAPPED storage until the operation completes or is canceled.
    let started = unsafe {
        ReadFile(
            stream,
            buffer.as_mut_ptr(),
            length,
            std::ptr::null_mut(),
            operation.as_mut_ptr(),
        )
    };
    finish_io(stream, &operation, started, deadline, cancellation).or_else(pipe_read_eof)
}

pub(crate) fn write_pipe(
    stream: HANDLE,
    buffer: &[u8],
    deadline: Option<Instant>,
) -> IoResult<usize> {
    reject_expired_deadline(deadline)?;
    let length = u32::try_from(buffer.len())
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "pipe write buffer is too large"))?;
    let mut operation = OverlappedOperation::new()?;
    // SAFETY: `stream` is an overlapped named-pipe handle, `buffer` remains live until completion,
    // and `operation` owns stable OVERLAPPED storage until the operation completes or is canceled.
    let started = unsafe {
        WriteFile(
            stream,
            buffer.as_ptr(),
            length,
            std::ptr::null_mut(),
            operation.as_mut_ptr(),
        )
    };
    finish_io(stream, &operation, started, deadline, None)
}

fn finish_io(
    stream: HANDLE,
    operation: &OverlappedOperation,
    started: i32,
    deadline: Option<Instant>,
    cancellation: Option<HANDLE>,
) -> IoResult<usize> {
    if started == 0 {
        let error = Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING.cast_signed()) {
            return Err(error);
        }
    }

    let timeout = deadline.map_or(INFINITE, deadline_timeout);
    // SAFETY: Each supplied event remains live for the wait. The operation event is signaled on
    // I/O completion, and the optional manual-reset event is signaled on association shutdown.
    let wait = unsafe {
        match cancellation {
            Some(cancellation) => {
                let events = [operation.event(), cancellation];
                WaitForMultipleObjects(2, events.as_ptr(), 0, timeout)
            }
            None => WaitForSingleObject(operation.event(), timeout),
        }
    };
    match wait {
        WAIT_OBJECT_0 => operation.result(stream, false).map(|bytes| bytes as usize),
        wait if cancellation.is_some() && wait == WAIT_OBJECT_0 + 1 => {
            operation.cancel_and_wait(stream)?;
            Err(Error::new(
                ErrorKind::ConnectionAborted,
                "broker association shut down",
            ))
        }
        WAIT_TIMEOUT => {
            operation.cancel_and_wait(stream)?;
            Err(Error::new(
                ErrorKind::TimedOut,
                "broker setup deadline elapsed",
            ))
        }
        WAIT_FAILED => {
            let error = Error::last_os_error();
            operation.cancel_and_wait(stream)?;
            Err(error)
        }
        _ => unreachable!("WaitForSingleObject returned an unknown status"),
    }
}

fn deadline_timeout(deadline: Instant) -> u32 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let milliseconds =
        remaining.as_millis() + u128::from(!remaining.subsec_nanos().is_multiple_of(1_000_000));
    u32::try_from(milliseconds.min(u128::from(INFINITE - 1)))
        .expect("deadline timeout is clamped to u32")
}

fn reject_expired_deadline(deadline: Option<Instant>) -> IoResult<()> {
    if deadline.is_some_and(|deadline| deadline <= Instant::now()) {
        return Err(Error::new(
            ErrorKind::TimedOut,
            "broker setup deadline elapsed",
        ));
    }
    Ok(())
}

fn pipe_read_eof(error: Error) -> IoResult<usize> {
    match error.raw_os_error() {
        Some(code)
            if code == ERROR_BROKEN_PIPE.cast_signed()
                || code == ERROR_PIPE_NOT_CONNECTED.cast_signed() =>
        {
            Ok(0)
        }
        _ => Err(error),
    }
}

impl OverlappedOperation {
    pub(crate) fn new() -> IoResult<Self> {
        let event = OwnedEvent::manual_reset()?;
        let mut state = Box::<OVERLAPPED>::default();
        state.hEvent = event.0;
        Ok(Self { state, event })
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut OVERLAPPED {
        self.state.as_mut()
    }

    pub(crate) fn result(&self, stream: HANDLE, wait: bool) -> IoResult<u32> {
        let mut bytes = 0;
        // SAFETY: `stream` and this OVERLAPPED describe the same live operation, and `bytes` is
        // writable for the duration of the call.
        if unsafe { GetOverlappedResult(stream, self.state.as_ref(), &raw mut bytes, wait.into()) }
            == 0
        {
            return Err(Error::last_os_error());
        }
        Ok(bytes)
    }

    pub(crate) fn cancel_and_wait(&self, stream: HANDLE) -> IoResult<()> {
        // SAFETY: `stream` and this OVERLAPPED describe the same live operation.
        let cancel_error = if unsafe { CancelIoEx(stream, self.state.as_ref()) } == 0 {
            let error = Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NOT_FOUND.cast_signed()) {
                None
            } else {
                Some(error)
            }
        } else {
            None
        };
        let _ = self.result(stream, true);
        if let Some(error) = cancel_error {
            return Err(error);
        }
        Ok(())
    }

    fn event(&self) -> HANDLE {
        self.event.0
    }
}

impl OwnedEvent {
    pub(crate) fn manual_reset() -> IoResult<Self> {
        // SAFETY: The event is unnamed and uses no security descriptor.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(Error::last_os_error());
        }
        Ok(Self(event))
    }

    pub(crate) fn set(&self) -> IoResult<()> {
        // SAFETY: This is a live event handle returned by CreateEventW.
        if unsafe { SetEvent(self.0) } == 0 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedEvent {
    fn drop(&mut self) {
        // SAFETY: This is a live event handle returned by CreateEventW.
        unsafe { CloseHandle(self.0) };
    }
}

// SAFETY: The event and heap-stable OVERLAPPED state may be completed or canceled from any
// process thread, and ownership prevents concurrent Rust access to the operation object.
unsafe impl Send for OverlappedOperation {}

// SAFETY: Windows event handles may be signaled and waited on from any process thread.
unsafe impl Send for OwnedEvent {}
// SAFETY: Shared access only passes the immutable handle value to thread-safe Windows APIs.
unsafe impl Sync for OwnedEvent {}

pub(crate) fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

pub(crate) fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

pub(crate) fn copy_io_error(error: &Error) -> Error {
    match error.raw_os_error() {
        Some(code) => Error::from_raw_os_error(code),
        None => Error::new(error.kind(), error.to_string()),
    }
}

pub(crate) fn ring_error(error: ControlRingError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker control ring: {error:?}"),
    )
}
