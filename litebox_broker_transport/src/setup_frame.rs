// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Portable length-prefixed setup framing.

use alloc::vec;
use alloc::vec::Vec;

/// Largest setup frame accepted or produced by broker transports.
pub const MAX_SETUP_FRAME_LEN: usize = 64 * 1024;

/// Failure while reading or writing a setup frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupFrameError<Error> {
    /// The concrete transport I/O operation failed.
    Io(Error),
    /// The peer closed after sending only part of the length prefix.
    TruncatedLength,
    /// The frame length was zero or exceeded [`MAX_SETUP_FRAME_LEN`].
    InvalidLength,
    /// The peer closed after sending only part of the frame body.
    TruncatedFrame,
    /// The concrete transport reported a zero-length write.
    WriteZero,
    /// The concrete transport reported more bytes than the supplied buffer.
    InvalidIoCount,
}

/// Reads one length-prefixed setup frame through `read`.
///
/// Returns `Ok(None)` when the peer closes before starting a new frame. The
/// callback must handle platform-specific deadlines. Errors selected by
/// `is_interrupted` are retried without discarding partial frame progress.
pub fn read_setup_frame<Error>(
    mut read: impl FnMut(&mut [u8]) -> Result<usize, Error>,
    mut is_interrupted: impl FnMut(&Error) -> bool,
) -> Result<Option<Vec<u8>>, SetupFrameError<Error>> {
    let mut length = [0; 4];
    let mut completed = 0;
    while completed < length.len() {
        let remaining = length.len() - completed;
        let read = match read(&mut length[completed..]) {
            Ok(read) => read,
            Err(error) if is_interrupted(&error) => continue,
            Err(error) => return Err(SetupFrameError::Io(error)),
        };
        match read {
            0 if completed == 0 => return Ok(None),
            0 => return Err(SetupFrameError::TruncatedLength),
            read if read > remaining => return Err(SetupFrameError::InvalidIoCount),
            read => completed += read,
        }
    }

    let length = u32::from_le_bytes(length) as usize;
    if length == 0 || length > MAX_SETUP_FRAME_LEN {
        return Err(SetupFrameError::InvalidLength);
    }

    let mut frame = vec![0; length];
    let mut completed = 0;
    while completed < frame.len() {
        let remaining = frame.len() - completed;
        let read = match read(&mut frame[completed..]) {
            Ok(read) => read,
            Err(error) if is_interrupted(&error) => continue,
            Err(error) => return Err(SetupFrameError::Io(error)),
        };
        match read {
            0 => return Err(SetupFrameError::TruncatedFrame),
            read if read > remaining => return Err(SetupFrameError::InvalidIoCount),
            read => completed += read,
        }
    }
    Ok(Some(frame))
}

/// Writes one length-prefixed setup frame through `write`.
///
/// The callback must handle platform-specific deadlines. Errors selected by
/// `is_interrupted` are retried without discarding partial frame progress.
pub fn write_setup_frame<Error>(
    frame: &[u8],
    mut write: impl FnMut(&[u8]) -> Result<usize, Error>,
    mut is_interrupted: impl FnMut(&Error) -> bool,
) -> Result<(), SetupFrameError<Error>> {
    if frame.is_empty() || frame.len() > MAX_SETUP_FRAME_LEN {
        return Err(SetupFrameError::InvalidLength);
    }
    let length = u32::try_from(frame.len()).map_err(|_| SetupFrameError::InvalidLength)?;
    write_all(&length.to_le_bytes(), &mut write, &mut is_interrupted)?;
    write_all(frame, write, is_interrupted)
}

fn write_all<Error>(
    mut bytes: &[u8],
    mut write: impl FnMut(&[u8]) -> Result<usize, Error>,
    mut is_interrupted: impl FnMut(&Error) -> bool,
) -> Result<(), SetupFrameError<Error>> {
    while !bytes.is_empty() {
        let written = match write(bytes) {
            Ok(written) => written,
            Err(error) if is_interrupted(&error) => continue,
            Err(error) => return Err(SetupFrameError::Io(error)),
        };
        match written {
            0 => return Err(SetupFrameError::WriteZero),
            written if written > bytes.len() => return Err(SetupFrameError::InvalidIoCount),
            written => bytes = &bytes[written..],
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_io_round_trips() {
        let mut encoded = Vec::new();
        write_setup_frame::<()>(
            b"frame",
            |bytes| {
                let written = bytes.len().min(2);
                encoded.extend_from_slice(&bytes[..written]);
                Ok(written)
            },
            |()| false,
        )
        .unwrap();

        let mut remaining = encoded.as_slice();
        let decoded = read_setup_frame::<()>(
            |buffer| {
                let read = remaining.len().min(buffer.len()).min(1);
                buffer[..read].copy_from_slice(&remaining[..read]);
                remaining = &remaining[read..];
                Ok(read)
            },
            |()| false,
        )
        .unwrap();
        assert_eq!(decoded.as_deref(), Some(b"frame".as_slice()));
    }

    #[test]
    fn interruption_retries_remaining_prefix() {
        let encoded = [1, 0, 0, 0, 42];
        let mut call = 0;
        let mut remaining = encoded.as_slice();
        let decoded = read_setup_frame(
            |buffer| {
                call += 1;
                match call {
                    1 => {
                        assert_eq!(buffer.len(), 4);
                        buffer[0] = remaining[0];
                        remaining = &remaining[1..];
                        Ok(1)
                    }
                    2 => {
                        assert_eq!(buffer.len(), 3);
                        Err(true)
                    }
                    3 => {
                        assert_eq!(buffer.len(), 3);
                        buffer.copy_from_slice(&remaining[..3]);
                        remaining = &remaining[3..];
                        Ok(3)
                    }
                    _ => {
                        assert_eq!(buffer.len(), 1);
                        buffer[0] = remaining[0];
                        remaining = &remaining[1..];
                        Ok(1)
                    }
                }
            },
            |error| *error,
        )
        .unwrap();
        assert_eq!(decoded.as_deref(), Some([42].as_slice()));
    }

    #[test]
    fn rejects_invalid_boundaries_and_io_counts() {
        assert_eq!(read_setup_frame::<()>(|_| Ok(0), |()| false), Ok(None));
        assert_eq!(
            write_setup_frame::<()>(b"", |_| Ok(0), |()| false),
            Err(SetupFrameError::InvalidLength),
        );
        assert_eq!(
            read_setup_frame::<()>(|buffer| Ok(buffer.len() + 1), |()| false),
            Err(SetupFrameError::InvalidIoCount),
        );
        assert_eq!(
            write_setup_frame::<()>(b"frame", |buffer| Ok(buffer.len() + 1), |()| false),
            Err(SetupFrameError::InvalidIoCount),
        );
    }
}
