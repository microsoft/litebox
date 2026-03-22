// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! 9P transport layer abstraction
//!
//! This module defines traits for reading and writing 9P protocol messages over
//! an underlying transport (e.g., TCP socket, virtio-9p, etc.).

use alloc::vec::Vec;

#[derive(Debug)]
pub enum ReadError {
    Io,
    Interrupted,
}

#[derive(Debug)]
pub enum WriteError {
    Io,
    Interrupted,
}

/// Trait for reading bytes from a transport
pub trait Read {
    /// Read bytes into the buffer
    ///
    /// Returns the number of bytes read
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ReadError>;

    /// Read exactly `buf.len()` bytes into the buffer.
    ///
    /// Retries on `Interrupted` to avoid abandoning a partially-read message,
    /// which would leave the TCP stream in an unrecoverable state.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), ReadError> {
        let mut total_read = 0;
        while total_read < buf.len() {
            match self.read(&mut buf[total_read..]) {
                Ok(0) => return Err(ReadError::Io),
                Ok(n) => total_read += n,
                Err(ReadError::Interrupted) => {
                    // Retry — abandoning a partial read would corrupt the stream.
                    core::hint::spin_loop();
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Trait for writing bytes to a transport
pub trait Write {
    /// Write bytes from the buffer
    ///
    /// Returns the number of bytes written
    fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError>;

    /// Write all bytes from the buffer.
    ///
    /// Retries on `Interrupted` to avoid abandoning a partially-written message,
    /// which would leave the TCP stream in an unrecoverable state.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), WriteError> {
        let mut total_written = 0;
        while total_written < buf.len() {
            match self.write(&buf[total_written..]) {
                Ok(0) => return Err(WriteError::Io),
                Ok(n) => total_written += n,
                Err(WriteError::Interrupted) => {
                    // Retry — abandoning a partial write would corrupt the stream.
                    core::hint::spin_loop();
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Write a 9P message to a transport
pub(super) fn write_message<W: Write>(
    w: &mut W,
    buf: &mut Vec<u8>,
    fcall: super::fcall::TaggedFcall<'_>,
) -> Result<(), WriteError> {
    fcall.encode_to_buf(buf)?;
    w.write_all(&buf[..])
}

/// Read a 9P message size header (4 bytes) and then the full message
pub(super) fn read_to_buf<R: Read + ?Sized>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> Result<(), super::Error> {
    buf.resize(4, 0);
    r.read_exact(&mut buf[..]).map_err(|e| match e {
        ReadError::Interrupted => super::Error::Interrupted,
        ReadError::Io => super::Error::Io,
    })?;
    let sz = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    if sz < 7 {
        // Minimum message size: size(4) + type(1) + tag(2)
        return Err(super::Error::InvalidResponse);
    }
    if sz > buf.capacity() {
        buf.reserve(sz - buf.len());
    }
    buf.resize(sz, 0);
    r.read_exact(&mut buf[4..]).map_err(|e| match e {
        ReadError::Interrupted => super::Error::Interrupted,
        ReadError::Io => super::Error::Io,
    })
}

/// Read a 9P message from a transport
pub(super) fn read_message<'a, R: Read>(
    r: &mut R,
    buf: &'a mut Vec<u8>,
) -> Result<super::fcall::TaggedFcall<'a>, super::Error> {
    read_to_buf(r, buf)?;
    super::fcall::TaggedFcall::decode(&buf[..])
}

impl Write for &mut [u8] {
    fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        let amt = self.len().min(buf.len());
        let (a, b) = core::mem::take(self).split_at_mut(amt);
        a.copy_from_slice(&buf[..amt]);
        *self = b;
        Ok(amt)
    }
}

impl Write for Vec<u8> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, WriteError> {
        self.extend_from_slice(buf);
        Ok(buf.len())
    }
}
