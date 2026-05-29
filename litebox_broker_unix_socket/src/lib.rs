// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This crate deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, wire, channel, client, core, and server crates.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use litebox_broker_channel::{
    ClientControlChannel, PeerCredential, ReceivedBrokerRequest, ReceivedBrokerResponse,
    ServerControlChannel,
};
use litebox_broker_protocol::{BrokerRequest, BrokerResponse};
use litebox_broker_wire::{decode_request, decode_response, encode_request, encode_response};

const MAX_FRAME_LEN: usize = 64 * 1024;

/// Client-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamClientControlChannel {
    stream: UnixStream,
}

impl UnixStreamClientControlChannel {
    /// Creates a client control channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }
}

/// Server-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamServerControlChannel {
    stream: UnixStream,
}

impl UnixStreamServerControlChannel {
    /// Creates a server control channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self { stream }
    }
}

impl ClientControlChannel for UnixStreamClientControlChannel {
    type Error = io::Error;

    fn send_request(&mut self, request: &BrokerRequest) -> io::Result<()> {
        write_frame(
            &mut self.stream,
            &encode_request(*request).map_err(wire_error)?,
        )
    }

    fn recv_response(&mut self) -> io::Result<Option<ReceivedBrokerResponse>> {
        let Some(frame) = read_frame(&mut self.stream)? else {
            return Ok(None);
        };
        decode_response(&frame).map(Some).map_err(wire_error)
    }
}

impl ServerControlChannel for UnixStreamServerControlChannel {
    type Error = io::Error;

    fn peer_credential(&self) -> io::Result<PeerCredential> {
        // TODO(split-broker): replace the PoC placeholder with Unix peer credential extraction
        // before this channel is used as an authenticated deployment boundary.
        Ok(PeerCredential::Unauthenticated)
    }

    fn recv_request(&mut self) -> io::Result<Option<ReceivedBrokerRequest>> {
        let Some(frame) = read_frame(&mut self.stream)? else {
            return Ok(None);
        };
        decode_request(&frame).map(Some).map_err(wire_error)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> io::Result<()> {
        write_frame(
            &mut self.stream,
            &encode_response(*response).map_err(wire_error)?,
        )
    }
}

fn read_frame(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0; 4];
    let mut read = 0;
    while read < len_buf.len() {
        match stream.read(&mut len_buf[read..]) {
            Ok(0) if read == 0 => return Ok(None),
            Ok(0) => return Err(invalid_data("truncated broker frame length")),
            Ok(len) => read += len,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }

    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }

    let mut frame = vec![0; len];
    stream.read_exact(&mut frame).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            invalid_data("truncated broker frame")
        } else {
            error
        }
    })?;
    Ok(Some(frame))
}

fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let len = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(frame)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wire_error(error: litebox_broker_wire::WireError) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid broker wire message: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        write_frame(&mut writer, &[1, 2, 3]).unwrap();

        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), [1, 2, 3]);
    }

    #[test]
    fn clean_eof_before_frame_is_close() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);

        assert!(read_frame(&mut reader).unwrap().is_none());
    }

    #[test]
    fn malformed_frames_are_invalid() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&[1, 0]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes())
            .unwrap();
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame(&mut reader).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
