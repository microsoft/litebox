// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Unix-domain-socket broker channel for hosted userland deployments.
//!
//! This module deliberately uses `std` because Unix-domain sockets and `std::io`
//! framing are hosted userland concerns. Portable broker interfaces live in the
//! no_std protocol, local, core, and host crates.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use litebox_broker_protocol::wire::{
    WireError, decode_request, decode_response, encode_request, encode_response,
};
use litebox_broker_protocol::{
    BrokerRequest, BrokerResponse, HostControlChannel, LocalControlChannel, PeerCredential,
};

const MAX_FRAME_LEN: usize = 64 * 1024;

/// Local-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamLocalControlChannel {
    stream: UnixStream,
    io_timeout: Option<Duration>,
    io_deadline: Option<Instant>,
    active_request_deadline: Option<Instant>,
}

impl UnixStreamLocalControlChannel {
    /// Creates a local control channel from an already-connected Unix stream.
    pub const fn from_connected(stream: UnixStream) -> Self {
        Self {
            stream,
            io_timeout: None,
            io_deadline: None,
            active_request_deadline: None,
        }
    }

    /// Connects to a userland broker Unix socket.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        UnixStream::connect(path).map(Self::from_connected)
    }

    /// Sets the read and write timeout for broker control-channel operations.
    pub fn set_io_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.io_timeout = timeout;
        self.io_deadline = None;
        self.active_request_deadline = None;
        self.set_stream_io_timeout(timeout)
    }

    /// Sets a wall-clock deadline for broker control-channel operations.
    pub fn set_io_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.io_deadline = deadline;
        self.active_request_deadline = None;
        match deadline {
            Some(deadline) => self.set_stream_io_timeout(Some(io_timeout_for_deadline(deadline)?)),
            None => self.set_stream_io_timeout(self.io_timeout),
        }
    }

    fn set_stream_io_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)?;
        self.stream.set_write_timeout(timeout)
    }

    fn current_deadline(&mut self) -> io::Result<Option<Instant>> {
        if let Some(deadline) = self.io_deadline {
            return Ok(Some(deadline));
        }
        if let Some(deadline) = self.active_request_deadline {
            return Ok(Some(deadline));
        }
        let Some(timeout) = self.io_timeout else {
            return Ok(None);
        };
        let deadline = deadline_after(timeout)?;
        self.active_request_deadline = Some(deadline);
        Ok(Some(deadline))
    }

    fn clear_active_request_deadline(&mut self) -> io::Result<()> {
        if self.io_deadline.is_none() {
            self.active_request_deadline = None;
            self.set_stream_io_timeout(self.io_timeout)?;
        }
        Ok(())
    }
}

/// Host-side Unix-domain-socket control channel for the hosted userland POC.
pub struct UnixStreamHostControlChannel {
    stream: UnixStream,
    io_deadline: Option<Instant>,
}

impl UnixStreamHostControlChannel {
    /// Creates a host control channel from an accepted Unix stream.
    pub const fn from_accepted(stream: UnixStream) -> Self {
        Self {
            stream,
            io_deadline: None,
        }
    }

    /// Sets a wall-clock deadline for all broker control-channel operations.
    pub fn set_io_deadline(&mut self, deadline: Option<Instant>) -> io::Result<()> {
        self.io_deadline = deadline;
        if let Some(deadline) = deadline {
            let timeout = io_timeout_for_deadline(deadline)?;
            self.stream.set_read_timeout(Some(timeout))?;
            self.stream.set_write_timeout(Some(timeout))
        } else {
            self.stream.set_read_timeout(None)?;
            self.stream.set_write_timeout(None)
        }
    }
}

impl LocalControlChannel for UnixStreamLocalControlChannel {
    type Error = io::Error;

    fn send_request(&mut self, request: &BrokerRequest) -> io::Result<()> {
        let frame = encode_request(request.clone());
        let deadline = self.current_deadline()?;
        let result = write_frame_with_deadline(&mut self.stream, &frame, deadline);
        if result.is_err() {
            self.active_request_deadline = None;
        }
        result
    }

    fn recv_response(&mut self) -> io::Result<Option<BrokerResponse>> {
        let deadline = self.current_deadline()?;
        let result = match read_frame_with_deadline(&mut self.stream, deadline)? {
            Some(frame) => decode_response(&frame).map(Some).map_err(wire_error),
            None => Ok(None),
        };
        self.clear_active_request_deadline()?;
        result
    }
}

impl HostControlChannel for UnixStreamHostControlChannel {
    type Error = io::Error;

    fn peer_credential(&self) -> io::Result<PeerCredential> {
        // TODO(broker): replace the PoC placeholder with Unix peer credential extraction
        // before this channel is used as an authenticated deployment boundary.
        Ok(PeerCredential::Unauthenticated)
    }

    fn recv_request(&mut self) -> io::Result<Option<BrokerRequest>> {
        let Some(frame) = read_frame_with_deadline(&mut self.stream, self.io_deadline)? else {
            return Ok(None);
        };
        decode_request(&frame).map(Some).map_err(wire_error)
    }

    fn send_response(&mut self, response: &BrokerResponse) -> io::Result<()> {
        write_frame_with_deadline(
            &mut self.stream,
            &encode_response(response.clone()),
            self.io_deadline,
        )
    }
}

fn read_frame_with_deadline(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0; 4];
    let mut read = 0;
    while read < len_buf.len() {
        refresh_stream_io_deadline(stream, deadline)?;
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
    let mut read = 0;
    while read < frame.len() {
        refresh_stream_io_deadline(stream, deadline)?;
        match stream.read(&mut frame[read..]) {
            Ok(0) => return Err(invalid_data("truncated broker frame")),
            Ok(len) => read += len,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Some(frame))
}

fn write_frame_with_deadline(
    stream: &mut UnixStream,
    frame: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    if frame.is_empty() || frame.len() > MAX_FRAME_LEN {
        return Err(invalid_data("invalid broker frame length"));
    }
    let len = u32::try_from(frame.len()).map_err(|_| invalid_data("broker frame too large"))?;
    write_all_with_deadline(stream, &len.to_le_bytes(), deadline)?;
    write_all_with_deadline(stream, frame, deadline)
}

fn write_all_with_deadline(
    stream: &mut UnixStream,
    mut buffer: &[u8],
    deadline: Option<Instant>,
) -> io::Result<()> {
    while !buffer.is_empty() {
        refresh_stream_io_deadline(stream, deadline)?;
        match stream.write(buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write broker frame",
                ));
            }
            Ok(written) => buffer = &buffer[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn refresh_stream_io_deadline(stream: &UnixStream, deadline: Option<Instant>) -> io::Result<()> {
    if let Some(deadline) = deadline {
        let timeout = io_timeout_for_deadline(deadline)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
    }
    Ok(())
}

fn io_timeout_for_deadline(deadline: Instant) -> io::Result<Duration> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|timeout| !timeout.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "broker I/O deadline expired"))?;
    Ok(timeout)
}

fn deadline_after(timeout: Duration) -> io::Result<Instant> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "broker I/O timeout overflow"))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wire_error(error: WireError) -> io::Error {
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
        write_frame_with_deadline(&mut writer, &[1, 2, 3], None).unwrap();

        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .unwrap(),
            [1, 2, 3]
        );
    }

    #[test]
    fn clean_eof_before_frame_is_close() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        drop(writer);

        assert!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_frames_are_invalid() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&[1, 0]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&0u32.to_le_bytes()).unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer
            .write_all(&u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_le_bytes())
            .unwrap();
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        writer.write_all(&4u32.to_le_bytes()).unwrap();
        writer.write_all(&[1, 2]).unwrap();
        drop(writer);
        assert_eq!(
            read_frame_with_deadline(&mut reader, None)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn local_response_read_io_timeout_is_wall_clock() {
        let (mut host_stream, local_stream) = UnixStream::pair().unwrap();
        let mut channel = UnixStreamLocalControlChannel::from_connected(local_stream);
        channel
            .set_io_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let reader = std::thread::spawn(move || channel.recv_response().unwrap_err());
        host_stream.write_all(&8u32.to_le_bytes()).unwrap();
        for _ in 0..8 {
            std::thread::sleep(Duration::from_millis(20));
            if host_stream.write_all(&[0]).is_err() {
                break;
            }
        }

        let error = reader.join().expect("timeout reader panicked");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected timeout error kind: {error:?}"
        );
    }
}
