// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable Linux memfd-backed shared memory.

use std::io::{Error, Result as IoResult};
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use std::sync::Mutex;
use std::time::Instant;

use rustix::fs::{
    MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, fstat, ftruncate, memfd_create,
};
use rustix::io::Errno;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use litebox_broker_protocol::shared_memory::{SharedMemory, SharedMemoryError};

use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};

const REQUIRED_MEMFD_SEALS: SealFlags = SealFlags::from_bits_retain(
    SealFlags::GROW.bits() | SealFlags::SHRINK.bits() | SealFlags::SEAL.bits(),
);

/// Linux memfd-backed shared memory usable by broker transports.
pub struct MemfdSharedMemory {
    fd: OwnedFd,
    mapping: Mutex<MappedRegion>,
}

struct MappedRegion {
    address: NonNull<u8>,
    length: usize,
}

// SAFETY: `MappedRegion` exclusively owns its mapping, and all byte access is
// serialized by the enclosing `Mutex`.
unsafe impl Send for MappedRegion {}

impl MemfdSharedMemory {
    /// Creates and maps a sealed memfd with `length` bytes.
    pub fn create(length: usize) -> IoResult<Self> {
        if length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        let fd = memfd_create(
            "litebox-broker-shm",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        )?;
        ftruncate(
            &fd,
            length
                .try_into()
                .map_err(|_| invalid_data("shared-memory length exceeds u64"))?,
        )?;
        fcntl_add_seals(&fd, REQUIRED_MEMFD_SEALS)?;
        Self::map(fd, length)
    }

    /// Validates and maps a received memfd with `expected_length` bytes.
    ///
    /// The descriptor must have the expected nonzero size sealed against
    /// changes.
    pub fn from_received_fd(fd: OwnedFd, expected_length: usize) -> IoResult<Self> {
        if expected_length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        // Verify the size seals before reading the size so it cannot change
        // between validation and mapping.
        let seals = fcntl_get_seals(&fd)?;
        if !seals.contains(REQUIRED_MEMFD_SEALS) {
            return Err(invalid_data("shared-memory size is not sealed"));
        }
        let length = usize::try_from(fstat(&fd)?.st_size)
            .map_err(|_| invalid_data("invalid shared-memory length"))?;
        if length != expected_length {
            return Err(invalid_data(
                "shared-memory length does not match expected size",
            ));
        }
        Self::map(fd, length)
    }

    fn map(fd: OwnedFd, length: usize) -> IoResult<Self> {
        if length > isize::MAX as usize {
            return Err(invalid_data(
                "shared-memory length exceeds pointer offset range",
            ));
        }
        // SAFETY: `fd` refers to a file at least `length` bytes long. The
        // returned mapping is checked against `MAP_FAILED` and owned by
        // `MappedRegion`.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }
        let address =
            NonNull::new(address.cast()).ok_or_else(|| invalid_data("mmap returned null"))?;
        Ok(Self {
            fd,
            mapping: Mutex::new(MappedRegion { address, length }),
        })
    }
}

impl AsFd for MemfdSharedMemory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SharedMemory for MemfdSharedMemory {
    fn len(&self) -> usize {
        self.mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offset
            .checked_add(destination.len())
            .filter(|end| *end <= mapping.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        // SAFETY: The range was checked against the live mapping,
        // `destination` is valid for its full length, and no Rust reference is
        // created for the byte-addressed shared mapping.
        unsafe {
            libc::memcpy(
                destination.as_mut_ptr().cast(),
                mapping.address.as_ptr().add(offset).cast(),
                destination.len(),
            );
        }
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let mapping = self
            .mapping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        offset
            .checked_add(source.len())
            .filter(|end| *end <= mapping.length)
            .ok_or(SharedMemoryError::InvalidRange)?;
        // SAFETY: The range was checked against the live mapping, `source` is
        // valid for its full length, and no Rust reference is created for the
        // byte-addressed shared mapping.
        unsafe {
            libc::memcpy(
                mapping.address.as_ptr().add(offset).cast(),
                source.as_ptr().cast(),
                source.len(),
            );
        }
        Ok(())
    }
}

/// Sends one memfd-backed shared-memory resource over an exclusively owned
/// connected Unix stream.
///
/// `deadline` bounds setup I/O without leaving a changed socket timeout behind.
pub fn send_memfd(
    stream: &mut UnixStream,
    memory: &MemfdSharedMemory,
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        send_fd(stream, memory.as_fd(), deadline)
    })
}

/// Receives, validates, and maps one memfd-backed shared-memory resource.
///
/// `expected_length` supplies the trusted expected size. `deadline` bounds
/// setup I/O without leaving a changed socket timeout behind.
pub fn receive_memfd(
    stream: &mut UnixStream,
    expected_length: usize,
    deadline: Option<Instant>,
) -> IoResult<MemfdSharedMemory> {
    let fd = with_read_deadline(stream, deadline, receive_fd)?;
    MemfdSharedMemory::from_received_fd(fd, expected_length)
}

fn send_fd(stream: &mut UnixStream, fd: BorrowedFd<'_>, deadline: Option<Instant>) -> IoResult<()> {
    // Unix streams require an ordinary data byte to carry ancillary data.
    let carrier = [0];
    let io = [IoSlice::new(&carrier)];
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
                    "failed to send shared-memory descriptor",
                ));
            }
            Ok(_) => return Err(invalid_data("oversized shared-memory setup write")),
            Err(Errno::INTR) => {}
            Err(error) => return Err(error.into()),
        }
    }
}

fn receive_fd(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<OwnedFd> {
    let mut carrier = [0];
    let mut io = [IoSliceMut::new(&mut carrier)];
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
    if received.bytes != carrier.len()
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
    Ok(received_fds
        .pop()
        .expect("exactly one received descriptor was validated"))
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        // SAFETY: `address` and `length` describe the mapping exclusively owned
        // by this value, and it is unmapped exactly once here.
        let result = unsafe { libc::munmap(self.address.as_ptr().cast(), self.length) };
        debug_assert_eq!(result, 0, "failed to unmap broker shared memory");
    }
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::io::FdFlags;
    use std::io::Write;
    use std::time::Duration;

    #[test]
    fn mappings_share_bytes_and_validate_ranges() {
        let first = MemfdSharedMemory::create(64).unwrap();
        let second =
            MemfdSharedMemory::from_received_fd(first.as_fd().try_clone_to_owned().unwrap(), 64)
                .unwrap();

        first.write(0, &[1, 2, 3]).unwrap();
        let mut data = [0; 3];
        second.read(0, &mut data).unwrap();
        assert_eq!(data, [1, 2, 3]);

        assert_eq!(
            second.write(63, &[1, 2]),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second.read(usize::MAX, &mut data),
            Err(SharedMemoryError::InvalidRange)
        );
    }

    #[test]
    fn rejects_unsealed_mismatched_and_oversized_mappings() {
        let fd = memfd_create("litebox-broker-shm-test", MemfdFlags::CLOEXEC).unwrap();
        ftruncate(&fd, 1).unwrap();
        assert_eq!(
            MemfdSharedMemory::from_received_fd(fd, 1)
                .err()
                .expect("unsealed memfd should fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let memory = MemfdSharedMemory::create(64).unwrap();
        assert_eq!(
            MemfdSharedMemory::from_received_fd(memory.as_fd().try_clone_to_owned().unwrap(), 32,)
                .err()
                .expect("mismatched memfd size should fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let fd = memfd_create("litebox-broker-shm-test", MemfdFlags::CLOEXEC).unwrap();
        assert_eq!(
            MemfdSharedMemory::map(fd, isize::MAX as usize + 1)
                .err()
                .expect("oversized mapping should fail")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn transfers_exact_size_memory_with_close_on_exec() {
        let length = 24;
        let memory = MemfdSharedMemory::create(length).unwrap();
        memory.write(16, &[1, 2, 3]).unwrap();
        let (mut local_stream, mut host_stream) = UnixStream::pair().unwrap();

        send_memfd(&mut host_stream, &memory, None).unwrap();
        let mapped_memory = receive_memfd(&mut local_stream, length, None).unwrap();
        let mut bytes = [0; 3];
        mapped_memory.read(16, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3]);
        let flags = rustix::io::fcntl_getfd(mapped_memory.as_fd()).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn rejects_missing_multiple_and_truncated_descriptors() {
        let length = 8;

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        sender.write_all(&[0]).unwrap();
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
                .err()
                .expect("missing descriptor must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let memory = MemfdSharedMemory::create(length).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(&mut sender, &[memory.as_fd(), memory.as_fd()]);
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
                .err()
                .expect("multiple descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        let fd = memory.as_fd();
        send_test_fds(&mut sender, &[fd, fd, fd, fd, fd]);
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
                .err()
                .expect("truncated descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn rejects_wrong_size_and_unsealed_memory() {
        let length = 8;

        let wrong_size = MemfdSharedMemory::create(7).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_memfd(&mut sender, &wrong_size, None).unwrap();
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
                .err()
                .expect("wrong shared-memory size must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let unsealed = memfd_create("unsealed-transfer-test", MemfdFlags::CLOEXEC).unwrap();
        ftruncate(&unsealed, length.try_into().unwrap()).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(&mut sender, &[unsealed.as_fd()]);
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
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
            receive_memfd(&mut receiver, length, None)
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
            receive_memfd(&mut receiver, length, Some(expired))
                .err()
                .expect("expired setup deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(receiver.read_timeout().unwrap(), previous_timeout);

        let memory = MemfdSharedMemory::create(length).unwrap();
        let (_receiver, mut sender) = UnixStream::pair().unwrap();
        sender.set_write_timeout(previous_timeout).unwrap();
        assert_eq!(
            send_memfd(&mut sender, &memory, Some(expired))
                .expect_err("expired send deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(sender.write_timeout().unwrap(), previous_timeout);
    }

    fn send_test_fds(stream: &mut UnixStream, fds: &[BorrowedFd<'_>]) {
        let carrier = [0];
        let io = [IoSlice::new(&carrier)];
        let mut control_space =
            [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        assert_eq!(
            rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::NOSIGNAL).unwrap(),
            1
        );
    }
}
