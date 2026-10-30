// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub(crate) fn with_read_deadline<Output>(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
    operation: impl FnOnce(&mut UnixStream, Option<Instant>) -> IoResult<Output>,
) -> IoResult<Output> {
    let Some(_) = deadline else {
        return operation(stream, None);
    };
    let previous = stream.read_timeout()?;
    let result = operation(stream, deadline);
    let restore = ignore_disconnected_socket(stream.set_read_timeout(previous));
    combine_result_with_restore(result, restore)
}

pub(crate) fn with_write_deadline<Output>(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
    operation: impl FnOnce(&mut UnixStream, Option<Instant>) -> IoResult<Output>,
) -> IoResult<Output> {
    let Some(_) = deadline else {
        return operation(stream, None);
    };
    let previous = stream.write_timeout()?;
    let result = operation(stream, deadline);
    let restore = ignore_disconnected_socket(stream.set_write_timeout(previous));
    combine_result_with_restore(result, restore)
}

pub(crate) fn refresh_read_deadline(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> IoResult<()> {
    if let Some(deadline) = deadline {
        let timeout = io_timeout_for_deadline(deadline)?;
        ignore_disconnected_socket(stream.set_read_timeout(Some(timeout)))?;
    }
    Ok(())
}

pub(crate) fn refresh_write_deadline(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> IoResult<()> {
    if let Some(deadline) = deadline {
        let timeout = io_timeout_for_deadline(deadline)?;
        ignore_disconnected_socket(stream.set_write_timeout(Some(timeout)))?;
    }
    Ok(())
}

/// Treats `EINVAL` from setting a socket timeout as success.
///
/// XNU rejects `SO_RCVTIMEO`/`SO_SNDTIMEO` with `EINVAL` once the socket is
/// disconnected, where Linux accepts them. A disconnected socket cannot block,
/// so the I/O proceeds without the timeout and reports EOF or `EPIPE` itself.
fn ignore_disconnected_socket(result: IoResult<()>) -> IoResult<()> {
    match result {
        Err(error) if error.raw_os_error() == Some(libc::EINVAL) => Ok(()),
        result => result,
    }
}

fn combine_result_with_restore<Output>(
    result: IoResult<Output>,
    restore: IoResult<()>,
) -> IoResult<Output> {
    match (result, restore) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(restore)) => Err(Error::new(
            operation.kind(),
            format!("{operation}; additionally failed to restore socket timeout: {restore}"),
        )),
    }
}

pub(crate) fn io_timeout_for_deadline(deadline: Instant) -> IoResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| Error::new(ErrorKind::TimedOut, "broker setup deadline expired"))
}
