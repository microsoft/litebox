// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix setup framing and failure helpers shared by both association sides.
//!
//! The local and host endpoints in [`crate::unix_socket`] must frame setup
//! traffic and report failures identically, so this crate-private module is the
//! single source of that security-sensitive framing instead of each endpoint
//! reimplementing it.
//!
//! Setup framing is a property of this macOS-userland binding, not of the
//! broker wire protocol; portable messages live in `litebox_broker_protocol`.

use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use litebox_broker_protocol::wire::WireError;
use litebox_broker_transport::ring_association::AssociationStream;
#[cfg(test)]
use litebox_broker_transport::setup_frame::MAX_SETUP_FRAME_LEN;
use litebox_broker_transport::setup_frame::{
    SetupFrameError, read_setup_frame as read_frame, write_setup_frame as write_frame,
};

use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};

/// Reads one length-prefixed setup frame, bounded by `deadline`.
///
/// Returns `Ok(None)` when the peer closed cleanly on a frame boundary.
pub(crate) fn read_setup_frame(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> IoResult<Option<Vec<u8>>> {
    with_read_deadline(stream, deadline, |stream, deadline| {
        read_frame(
            |buffer| {
                refresh_read_deadline(stream, deadline)?;
                stream.read(buffer)
            },
            |error| error.kind() == ErrorKind::Interrupted,
        )
        .map_err(frame_error)
    })
}

/// Writes one length-prefixed setup frame, bounded by `deadline`.
pub(crate) fn write_setup_frame(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        write_frame(
            frame,
            |buffer| {
                refresh_write_deadline(stream, deadline)?;
                stream.write(buffer)
            },
            |error| error.kind() == ErrorKind::Interrupted,
        )
        .map_err(frame_error)
    })
}

fn frame_error(error: SetupFrameError<Error>) -> Error {
    match error {
        SetupFrameError::Io(error) => error,
        SetupFrameError::TruncatedLength => invalid_data("truncated broker setup frame length"),
        SetupFrameError::InvalidLength => invalid_data("invalid broker setup frame length"),
        SetupFrameError::TruncatedFrame => invalid_data("truncated broker setup frame"),
        SetupFrameError::WriteZero => {
            Error::new(ErrorKind::WriteZero, "failed to write broker setup frame")
        }
        SetupFrameError::InvalidIoCount => Error::other("invalid broker setup frame I/O count"),
    }
}

/// Shuts down both directions of an association socket, tolerating a peer that
/// already disconnected.
fn shutdown_socket(stream: &UnixStream) -> IoResult<()> {
    match stream.shutdown(Shutdown::Both) {
        Err(error) if error.kind() == ErrorKind::NotConnected => Ok(()),
        result => result,
    }
}

/// The setup socket of a negotiated association, which activation retains for
/// liveness and teardown.
pub(crate) struct UnixAssociationStream {
    stream: UnixStream,
    /// A duplicate of `stream` that teardown shuts down, so a sandbox can
    /// permit shutting down only this descriptor.
    shutdown_stream: Arc<UnixStream>,
    setup_deadline: Option<Instant>,
}

impl UnixAssociationStream {
    /// Wraps `stream`, bounding the remaining setup I/O by `setup_deadline`.
    pub(crate) fn new(stream: UnixStream, setup_deadline: Option<Instant>) -> IoResult<Self> {
        Ok(Self {
            shutdown_stream: Arc::new(stream.try_clone()?),
            stream,
            setup_deadline,
        })
    }

    /// Returns the descriptor that teardown shuts down.
    pub(crate) fn shutdown_stream(&self) -> Arc<UnixStream> {
        Arc::clone(&self.shutdown_stream)
    }
}

impl AssociationStream for UnixAssociationStream {
    fn read_frame(&mut self) -> IoResult<Option<Vec<u8>>> {
        read_setup_frame(&mut self.stream, self.setup_deadline)
    }

    fn write_frame(&mut self, frame: &[u8]) -> IoResult<()> {
        write_setup_frame(&mut self.stream, frame, self.setup_deadline)
    }

    fn wait_for_close(&self) -> IoResult<()> {
        let mut byte = [0];
        loop {
            match (&self.stream).read(&mut byte) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(invalid_data(
                        "peer sent unexpected active control-socket data",
                    ));
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn shutdown(&self) -> IoResult<()> {
        shutdown_socket(&self.shutdown_stream)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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

    #[test]
    fn deadline_bounded_setup_io_reports_peer_close_as_eof() {
        let deadline = || Some(Instant::now() + Duration::from_secs(2));

        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);
        assert!(read_setup_frame(&mut reader, deadline()).unwrap().is_none());

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_setup_frame(&mut writer, &[1, 2, 3], None).unwrap();
        drop(writer);
        assert_eq!(
            read_setup_frame(&mut reader, deadline()).unwrap().unwrap(),
            [1, 2, 3]
        );
        assert!(read_setup_frame(&mut reader, deadline()).unwrap().is_none());

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_setup_frame(&mut reader, deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        assert_eq!(
            write_setup_frame(&mut writer, &[1, 2, 3], deadline())
                .unwrap_err()
                .kind(),
            ErrorKind::BrokenPipe
        );
    }
}
