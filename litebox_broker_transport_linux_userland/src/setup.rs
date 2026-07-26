// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix setup framing and failure helpers shared by both association sides.
//!
//! The local and host endpoints in [`crate::unix_socket`] must frame setup
//! traffic and report failures identically, so this crate-private module is the
//! single source of that security-sensitive framing instead of each endpoint
//! reimplementing it.
//!
//! Setup framing is a property of this Linux-userland binding, not of the
//! broker wire protocol; portable messages live in `litebox_broker_protocol`.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use litebox_broker_protocol::wire::WireError;
use litebox_broker_transport::control_ring::ControlRingError;

use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};

/// Largest setup frame either endpoint accepts or produces.
const MAX_SETUP_FRAME_LEN: usize = 64 * 1024;

/// Reads one length-prefixed setup frame, bounded by `deadline`.
///
/// Returns `Ok(None)` when the peer closed cleanly on a frame boundary.
pub(crate) fn read_setup_frame(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> IoResult<Option<Vec<u8>>> {
    with_read_deadline(stream, deadline, |stream, deadline| {
        let mut len_buf = [0; 4];
        let mut read = 0;
        while read < len_buf.len() {
            refresh_read_deadline(stream, deadline)?;
            match stream.read(&mut len_buf[read..]) {
                Ok(0) if read == 0 => return Ok(None),
                Ok(0) => return Err(invalid_data("truncated broker setup frame length")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }

        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_SETUP_FRAME_LEN {
            return Err(invalid_data("invalid broker setup frame length"));
        }

        let mut frame = vec![0; len];
        let mut read = 0;
        while read < frame.len() {
            refresh_read_deadline(stream, deadline)?;
            match stream.read(&mut frame[read..]) {
                Ok(0) => return Err(invalid_data("truncated broker setup frame")),
                Ok(len) => read += len,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(Some(frame))
    })
}

/// Writes one length-prefixed setup frame, bounded by `deadline`.
pub(crate) fn write_setup_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        if frame.is_empty() || frame.len() > MAX_SETUP_FRAME_LEN {
            return Err(invalid_data("invalid broker setup frame length"));
        }
        let len =
            u32::try_from(frame.len()).map_err(|_| invalid_data("broker setup frame too large"))?;
        write_all_with_deadline(stream, &len.to_le_bytes(), deadline)?;
        write_all_with_deadline(stream, frame, deadline)
    })
}

fn write_all_with_deadline(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    while !buffer.is_empty() {
        refresh_write_deadline(stream, deadline)?;
        match stream.write(buffer) {
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to write broker setup frame",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Shuts down both directions of an association socket, tolerating a peer that
/// already disconnected.
pub(crate) fn shutdown_socket(stream: &UnixStream) -> IoResult<()> {
    match stream.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

/// Builds the fail-closed error both endpoints report for malformed input.
pub(crate) fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

/// Maps a decode failure to the fail-closed error both endpoints report.
pub(crate) fn wire_error(error: WireError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

/// Clones an error so one recorded terminal failure can be reported to every
/// waiter of an association.
pub(crate) fn copy_io_error(error: &Error) -> Error {
    match error.raw_os_error() {
        Some(code) => Error::from_raw_os_error(code),
        None => Error::new(error.kind(), error.to_string()),
    }
}

/// Maps a control-ring failure to the fail-closed error both endpoints report.
pub(crate) fn ring_error(error: ControlRingError) -> Error {
    Error::new(
        ErrorKind::InvalidData,
        format!("invalid broker control ring: {error:?}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_frames_round_trip_and_reject_invalid_boundaries() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_setup_frame(&mut writer, &[1, 2, 3], None).unwrap();
        assert_eq!(
            read_setup_frame(&mut reader, None).unwrap().unwrap(),
            [1, 2, 3]
        );

        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);
        assert!(read_setup_frame(&mut reader, None).unwrap().is_none());

        for frame_prefix in [
            vec![1, 0],
            0u32.to_le_bytes().to_vec(),
            u32::try_from(MAX_SETUP_FRAME_LEN + 1)
                .unwrap()
                .to_le_bytes()
                .to_vec(),
        ] {
            let (mut writer, mut reader) = UnixStream::pair().unwrap();
            writer.write_all(&frame_prefix).unwrap();
            drop(writer);
            assert_eq!(
                read_setup_frame(&mut reader, None).unwrap_err().kind(),
                ErrorKind::InvalidData
            );
        }

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_setup_frame(&mut reader, None).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }
}
