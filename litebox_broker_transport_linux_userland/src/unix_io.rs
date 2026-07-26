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
    combine_result_with_restore(result, stream.set_read_timeout(previous))
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
    combine_result_with_restore(result, stream.set_write_timeout(previous))
}

pub(crate) fn refresh_read_deadline(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> IoResult<()> {
    if let Some(deadline) = deadline {
        stream.set_read_timeout(Some(io_timeout_for_deadline(deadline)?))?;
    }
    Ok(())
}

pub(crate) fn refresh_write_deadline(
    stream: &UnixStream,
    deadline: Option<Instant>,
) -> IoResult<()> {
    if let Some(deadline) = deadline {
        stream.set_write_timeout(Some(io_timeout_for_deadline(deadline)?))?;
    }
    Ok(())
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

fn io_timeout_for_deadline(deadline: Instant) -> IoResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| Error::new(ErrorKind::TimedOut, "broker setup deadline expired"))
}
