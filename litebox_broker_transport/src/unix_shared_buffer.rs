// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux shared-buffer exchange over connected Unix-domain sockets.
//!
//! These helpers establish an association-scoped buffer region before ordinary
//! broker framing begins. Callers must ensure exclusive access to the stream
//! during the exchange.

use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use litebox_broker_protocol::shared_memory::SharedBufferRegion;
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use crate::shared_memory::MemfdSharedMemory;

const SHARED_BUFFER_SETUP_VERSION: u8 = 1;

/// Creates a sealed Linux shared buffer region with `length` bytes.
pub fn create_shared_buffer_region(
    length: usize,
) -> IoResult<SharedBufferRegion<MemfdSharedMemory>> {
    let memory = MemfdSharedMemory::create(length)?;
    Ok(SharedBufferRegion::new(memory))
}

/// Sends one shared-buffer-region memfd over an exclusively owned connected stream.
///
/// `deadline` bounds setup I/O without leaving a changed socket timeout behind.
pub fn send_shared_buffer_region(
    stream: &mut UnixStream,
    region: &SharedBufferRegion<MemfdSharedMemory>,
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        send_fd(stream, region.memory().as_fd(), deadline)
    })
}

/// Receives, validates, and maps one shared-buffer-region memfd.
///
/// `expected_length` supplies the trusted expected size. `deadline` bounds
/// setup I/O without leaving a changed socket timeout behind.
pub fn receive_shared_buffer_region(
    stream: &mut UnixStream,
    expected_length: usize,
    deadline: Option<Instant>,
) -> IoResult<SharedBufferRegion<MemfdSharedMemory>> {
    let fd = with_read_deadline(stream, deadline, receive_fd)?;
    let memory = MemfdSharedMemory::from_received_fd(fd, expected_length)?;
    Ok(SharedBufferRegion::new(memory))
}

fn send_fd(stream: &mut UnixStream, fd: BorrowedFd<'_>, deadline: Option<Instant>) -> IoResult<()> {
    let marker = [SHARED_BUFFER_SETUP_VERSION];
    let io = [IoSlice::new(&marker)];
    let fds = [fd];
    let mut control_space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    assert!(
        control.push(SendAncillaryMessage::ScmRights(&fds)),
        "SCM_RIGHTS control buffer is correctly sized"
    );
    loop {
        refresh_write_deadline(stream, deadline)?;
        match rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::NOSIGNAL) {
            Ok(1) => return Ok(()),
            Ok(0) => {
                return Err(Error::new(
                    ErrorKind::WriteZero,
                    "failed to send shared buffer region",
                ));
            }
            Ok(_) => return Err(invalid_data("oversized shared-memory setup write")),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_fd(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<OwnedFd> {
    let mut marker = [0];
    let mut io = [IoSliceMut::new(&mut marker)];
    let mut control_space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let received = loop {
        refresh_read_deadline(stream, deadline)?;
        match rustix::net::recvmsg(
            stream.as_fd(),
            &mut io,
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        ) {
            Ok(received) => break received,
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    };

    let mut received_fds = Vec::new();
    let mut unexpected_control_message = false;
    for message in control.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(fds) => received_fds.extend(fds),
            _ => unexpected_control_message = true,
        }
    }

    if received.bytes == 0 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "broker closed during shared-memory setup",
        ));
    }
    if received.bytes != marker.len()
        || received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || unexpected_control_message
        || received_fds.len() != 1
    {
        return Err(invalid_data(
            "shared-memory setup contained invalid descriptor data",
        ));
    }
    if marker[0] != SHARED_BUFFER_SETUP_VERSION {
        return Err(invalid_data("unsupported shared-memory setup version"));
    }
    Ok(received_fds
        .pop()
        .expect("exactly one received descriptor was validated"))
}

fn with_read_deadline<Output>(
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

fn with_write_deadline<Output>(
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

fn refresh_read_deadline(stream: &UnixStream, deadline: Option<Instant>) -> IoResult<()> {
    if let Some(deadline) = deadline {
        stream.set_read_timeout(Some(io_timeout_for_deadline(deadline)?))?;
    }
    Ok(())
}

fn refresh_write_deadline(stream: &UnixStream, deadline: Option<Instant>) -> IoResult<()> {
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
        .ok_or_else(|| Error::new(ErrorKind::TimedOut, "shared-memory setup deadline expired"))
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::Shutdown;

    use litebox_broker_protocol::shared_memory::{SharedBufferDescriptor, SharedBufferError};
    use rustix::fs::{MemfdFlags, ftruncate, memfd_create};
    use rustix::io::FdFlags;

    #[test]
    fn transfers_exact_size_memory_with_close_on_exec() {
        let length = 24;
        let region = create_shared_buffer_region(length).unwrap();
        let descriptor = region.write(16, &[1, 2, 3]).unwrap();
        let (mut local_stream, mut host_stream) = UnixStream::pair().unwrap();

        send_shared_buffer_region(&mut host_stream, &region, None).unwrap();
        let mapped_region = receive_shared_buffer_region(&mut local_stream, length, None).unwrap();

        let mut bytes = [0; 3];
        mapped_region.read(descriptor, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        let flags = rustix::io::fcntl_getfd(mapped_region.memory().as_fd()).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn rejects_missing_multiple_and_truncated_descriptors() {
        let length = 8;

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        sender.write_all(&[SHARED_BUFFER_SETUP_VERSION]).unwrap();
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("missing descriptor must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let region = create_shared_buffer_region(length).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(
            &mut sender,
            SHARED_BUFFER_SETUP_VERSION,
            &[region.memory().as_fd(), region.memory().as_fd()],
        );
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("multiple descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        let fd = region.memory().as_fd();
        send_test_fds(
            &mut sender,
            SHARED_BUFFER_SETUP_VERSION,
            &[fd, fd, fd, fd, fd],
        );
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("truncated descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_wrong_version_size_and_unsealed_memory() {
        let length = 8;
        let region = create_shared_buffer_region(length).unwrap();

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(&mut sender, 2, &[region.memory().as_fd()]);
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("unsupported setup version must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let wrong_size = create_shared_buffer_region(7).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_shared_buffer_region(&mut sender, &wrong_size, None).unwrap();
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("wrong shared-memory size must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let unsealed = memfd_create("unsealed-transfer-test", MemfdFlags::CLOEXEC).unwrap();
        ftruncate(&unsealed, length.try_into().unwrap()).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(
            &mut sender,
            SHARED_BUFFER_SETUP_VERSION,
            &[unsealed.as_fd()],
        );
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("unsealed shared memory must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn reports_eof_and_expired_deadline() {
        let length = 8;
        let (mut receiver, sender) = UnixStream::pair().unwrap();
        drop(sender);
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, None)
                .err()
                .expect("setup EOF must be reported")
                .kind(),
            ErrorKind::UnexpectedEof
        );

        let (mut receiver, _sender) = UnixStream::pair().unwrap();
        let previous_timeout = Some(Duration::from_secs(2));
        receiver.set_read_timeout(previous_timeout).unwrap();
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        assert_eq!(
            receive_shared_buffer_region(&mut receiver, length, Some(expired))
                .err()
                .expect("expired setup deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(receiver.read_timeout().unwrap(), previous_timeout);

        let region = create_shared_buffer_region(length).unwrap();
        let (_receiver, mut sender) = UnixStream::pair().unwrap();
        sender.set_write_timeout(previous_timeout).unwrap();
        assert_eq!(
            send_shared_buffer_region(&mut sender, &region, Some(expired))
                .expect_err("expired send deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(sender.write_timeout().unwrap(), previous_timeout);
    }

    fn send_test_fds(stream: &mut UnixStream, marker: u8, fds: &[BorrowedFd<'_>]) {
        let marker = [marker];
        let io = [IoSlice::new(&marker)];
        let mut control_space =
            [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        assert_eq!(
            rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::NOSIGNAL).unwrap(),
            1
        );
    }

    #[test]
    fn descriptor_validation_remains_region_scoped() {
        assert_eq!(
            SharedBufferDescriptor::new(16, 1).range(16),
            Err(SharedBufferError::InvalidRange)
        );
    }

    #[test]
    fn dropping_stream_after_send_does_not_affect_mapping() {
        let length = 8;
        let region = create_shared_buffer_region(length).unwrap();
        let (mut local_stream, mut host_stream) = UnixStream::pair().unwrap();
        send_shared_buffer_region(&mut host_stream, &region, None).unwrap();
        host_stream.shutdown(Shutdown::Both).unwrap();

        let mapped_region = receive_shared_buffer_region(&mut local_stream, length, None).unwrap();
        mapped_region.write(0, &[7]).unwrap();
        let mut byte = [0];
        region
            .read(SharedBufferDescriptor::new(0, 1), &mut byte)
            .unwrap();
        assert_eq!(byte, [7]);
    }
}
