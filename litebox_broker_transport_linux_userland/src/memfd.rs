// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux memfd-backed broker association memory.
//!
//! One sealed memfd mapping backs an association shared-buffer pool or a shared
//! control ring. The mapping implements the portable shared-memory interfaces in
//! `litebox_broker_transport`, and its futex support lets portable control-ring
//! endpoints block and wake without knowing anything about Linux.
//!
//! Rust never dereferences the peer-writable mapping. Byte and word access uses
//! positional descriptor I/O into private buffers; the mapping exists only to
//! provide checked addresses to the kernel's futex operations.

use std::io::{Error, Result as IoResult};
use std::io::{ErrorKind, IoSlice, IoSliceMut};
use std::mem::{align_of, size_of};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use std::time::Instant;

use rustix::fs::{
    MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, fstat, ftruncate, memfd_create,
};
use rustix::io::{Errno, pread, pwrite};
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};

use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, WaitableSharedMemory, memory_permits_byte_range, memory_permits_u32,
    memory_permits_u64,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};

use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};

const REQUIRED_MEMFD_SEALS: SealFlags = SealFlags::from_bits_retain(
    SealFlags::GROW.bits() | SealFlags::SHRINK.bits() | SealFlags::SEAL.bits(),
);
const _: () = assert!(SHARED_BUFFER_POOL_SIZE != CONTROL_RING_MEMORY_SIZE);

/// Linux memfd-backed shared memory usable by broker transports.
pub struct MemfdSharedMemory {
    fd: OwnedFd,
    mapping: MappedRegion,
    policy: MemoryAccessPolicy,
}

struct MappedRegion {
    address: NonNull<u8>,
    length: usize,
}

/// Restricts each memfd to one non-overlapping portable access model.
///
/// Shared-buffer memfds permit only byte copies. Control-ring memfds permit
/// byte and typed-word operations only at offsets defined by the ring ABI.
#[derive(Clone, Copy)]
enum MemoryAccessPolicy {
    Bytes,
    ControlRing,
}

impl MemoryAccessPolicy {
    const fn for_length(length: usize) -> Self {
        if length == CONTROL_RING_MEMORY_SIZE {
            Self::ControlRing
        } else {
            Self::Bytes
        }
    }

    const fn permits_byte_range(self, offset: usize, length: usize) -> bool {
        match self {
            Self::Bytes => true,
            Self::ControlRing => memory_permits_byte_range(offset, length),
        }
    }

    const fn permits_u32(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing => memory_permits_u32(offset),
        }
    }

    const fn permits_u64(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing => memory_permits_u64(offset),
        }
    }
}

// SAFETY: Moving or sharing this owner does not move or invalidate its OS
// mapping. Its metadata is immutable, and mapped contents are never
// dereferenced by Rust.
unsafe impl Send for MappedRegion {}
// SAFETY: See the `Send` justification. Only checked raw futex addresses are
// derived from the mapping and passed to the kernel.
unsafe impl Sync for MappedRegion {}

fn validate_u64_offset(memory: &MemfdSharedMemory, offset: usize) -> Result<(), SharedMemoryError> {
    if !memory.policy.permits_u64(offset) {
        return Err(SharedMemoryError::InvalidRange);
    }
    checked_range(&memory.mapping, offset, size_of::<u64>(), align_of::<u64>())
}

fn checked_u32_address(
    memory: &MemfdSharedMemory,
    offset: usize,
) -> Result<*mut u32, SharedMemoryError> {
    if !memory.policy.permits_u32(offset) {
        return Err(SharedMemoryError::InvalidRange);
    }
    let byte_address =
        shared_address(&memory.mapping, offset, size_of::<u32>(), align_of::<u32>())?;
    // The runtime check above establishes the required alignment.
    #[allow(clippy::cast_ptr_alignment)]
    Ok(byte_address.cast::<u32>())
}

fn checked_range(
    mapping: &MappedRegion,
    offset: usize,
    size: usize,
    alignment: usize,
) -> Result<(), SharedMemoryError> {
    offset
        .checked_add(size)
        .filter(|end| *end <= mapping.length)
        .ok_or(SharedMemoryError::InvalidRange)?;
    if !offset.is_multiple_of(alignment) {
        return Err(SharedMemoryError::UnalignedWord);
    }
    Ok(())
}

fn shared_address(
    mapping: &MappedRegion,
    offset: usize,
    size: usize,
    alignment: usize,
) -> Result<*mut u8, SharedMemoryError> {
    checked_range(mapping, offset, size, alignment)?;
    Ok(mapping.address.as_ptr().wrapping_add(offset))
}

fn validate_nonoverlapping_word_ranges(
    store_offset: usize,
    increment_offset: usize,
) -> Result<(), SharedMemoryError> {
    let store_end = store_offset
        .checked_add(size_of::<u64>())
        .ok_or(SharedMemoryError::InvalidRange)?;
    let increment_end = increment_offset
        .checked_add(size_of::<u32>())
        .ok_or(SharedMemoryError::InvalidRange)?;
    if store_offset < increment_end && increment_offset < store_end {
        return Err(SharedMemoryError::InvalidRange);
    }
    Ok(())
}

fn read_exact_at(
    memory: &MemfdSharedMemory,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), SharedMemoryError> {
    let mut completed = 0;
    while completed < destination.len() {
        let file_offset =
            u64::try_from(offset + completed).map_err(|_| SharedMemoryError::InvalidRange)?;
        match pread(&memory.fd, &mut destination[completed..], file_offset) {
            Ok(0) => return Err(SharedMemoryError::AccessFailed),
            Ok(read) => completed += read,
            Err(Errno::INTR) => {}
            Err(_) => return Err(SharedMemoryError::AccessFailed),
        }
    }
    Ok(())
}

fn write_all_at(
    memory: &MemfdSharedMemory,
    offset: usize,
    source: &[u8],
) -> Result<(), SharedMemoryError> {
    let mut completed = 0;
    while completed < source.len() {
        let file_offset =
            u64::try_from(offset + completed).map_err(|_| SharedMemoryError::InvalidRange)?;
        match pwrite(&memory.fd, &source[completed..], file_offset) {
            Ok(0) => return Err(SharedMemoryError::AccessFailed),
            Ok(written) => completed += written,
            Err(Errno::INTR) => {}
            Err(_) => return Err(SharedMemoryError::AccessFailed),
        }
    }
    Ok(())
}

const FUTEX_INCREMENT_OPERATION: libc::c_int =
    (libc::FUTEX_OP_ADD << 28) | (libc::FUTEX_OP_CMP_EQ << 24) | (1 << 12);
const FUTEX_WAIT_RECHECK_TIMEOUT: libc::timespec = libc::timespec {
    tv_sec: 0,
    tv_nsec: 100_000_000,
};

// The rustix futex API requires `AtomicU32` references. Raw syscalls keep Rust
// references out of memory that a peer can modify through an uncontrolled fd.
fn futex_increment(address: *mut u32) -> IoResult<()> {
    // SAFETY: `address` is aligned and lies within the live shared mapping.
    // FUTEX_WAKE_OP atomically increments it in the kernel, so Rust never forms
    // an atomic reference that a peer could invalidate through another alias.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            address,
            libc::FUTEX_WAKE_OP,
            0,
            0,
            address,
            FUTEX_INCREMENT_OPERATION,
        )
    };
    if result == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn futex_wait(address: *mut u32, expected: u32) -> IoResult<()> {
    let timeout = FUTEX_WAIT_RECHECK_TIMEOUT;
    // SAFETY: `address` is aligned and lies within the live shared mapping. The
    // timeout and the other unused pointer are valid for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            address,
            libc::FUTEX_WAIT,
            expected,
            &raw const timeout,
            std::ptr::null::<u32>(),
            0,
        )
    };
    if result == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn futex_wake_one(address: *mut u32) -> IoResult<()> {
    // SAFETY: `address` is aligned and lies within the live shared mapping.
    let result = unsafe {
        libc::syscall(
            libc::SYS_futex,
            address,
            libc::FUTEX_WAKE,
            1,
            std::ptr::null::<libc::timespec>(),
            std::ptr::null::<u32>(),
            0,
        )
    };
    if result == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

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
        // SAFETY: `fd` refers to a file at least `length` bytes long. A null
        // address lets the kernel choose the mapping location, and
        // `MappedRegion` owns the returned mapping.
        let address = unsafe {
            mmap(
                std::ptr::null_mut(),
                length,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &fd,
                0,
            )
        }?;
        let address =
            NonNull::new(address.cast()).ok_or_else(|| invalid_data("mmap returned null"))?;
        Ok(Self {
            fd,
            mapping: MappedRegion { address, length },
            policy: MemoryAccessPolicy::for_length(length),
        })
    }
}

impl WaitableSharedMemory for MemfdSharedMemory {
    type Error = Error;

    fn wait_access_error(error: SharedMemoryError) -> Error {
        Error::new(ErrorKind::InvalidInput, error)
    }

    /// Waits while a shared `u32` still equals `expected`.
    ///
    /// A value change or signal interruption is reported as a successful,
    /// possibly spurious wakeup. A bounded wait also lets callers recheck
    /// trusted cancellation state if a hostile peer restores the sampled shared
    /// value after cancellation. The caller must recheck its wait condition.
    fn wait_while_equal(&self, offset: usize, expected: u32) -> IoResult<()> {
        let address = checked_u32_address(self, offset).map_err(Self::wait_access_error)?;
        match futex_wait(address, expected) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR | libc::ETIMEDOUT)
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Wakes one waiter blocked on a shared `u32`.
    fn wake_one(&self, offset: usize) -> IoResult<()> {
        let address = checked_u32_address(self, offset).map_err(Self::wait_access_error)?;
        futex_wake_one(address)
    }
}

impl AsFd for MemfdSharedMemory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SharedMemory for MemfdSharedMemory {
    fn len(&self) -> usize {
        self.mapping.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        checked_range(&self.mapping, offset, destination.len(), 1)?;
        if !self.policy.permits_byte_range(offset, destination.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        read_exact_at(self, offset, destination)
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        checked_range(&self.mapping, offset, source.len(), 1)?;
        if !self.policy.permits_byte_range(offset, source.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        write_all_at(self, offset, source)
    }
}

impl ControlRingMemory for MemfdSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        checked_u32_address(self, offset)?;
        let mut bytes = [0; size_of::<u32>()];
        read_exact_at(self, offset, &mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = checked_u32_address(self, offset)?;
        futex_increment(address).map_err(|_| SharedMemoryError::AccessFailed)
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        validate_u64_offset(self, offset)?;
        let mut bytes = [0; size_of::<u64>()];
        read_exact_at(self, offset, &mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        validate_u64_offset(self, offset)?;
        write_all_at(self, offset, &value.to_ne_bytes())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        validate_nonoverlapping_word_ranges(store_offset, increment_offset)?;
        validate_u64_offset(self, store_offset)?;
        let increment_address = checked_u32_address(self, increment_offset)?;
        write_all_at(self, store_offset, &value.to_ne_bytes())?;
        futex_increment(increment_address).map_err(|_| SharedMemoryError::AccessFailed)
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
        send_fd(stream, memory.fd.as_fd(), deadline)
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
        let result = unsafe { munmap(self.address.as_ptr().cast(), self.length) };
        debug_assert!(result.is_ok(), "failed to unmap broker shared memory");
    }
}

fn invalid_data(message: &'static str) -> Error {
    Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::shared_buffer::{
        SHARED_BUFFER_LAYOUT, SHARED_BUFFER_POOL_SIZE, SharedBufferSlotIndex,
    };
    use litebox_broker_transport::control_ring::{
        CONTROL_RING_MEMORY_SIZE, CONTROL_RING_SLOT_COUNT, ControlRing, ControlRingReadStatus,
        ControlRingWriteStatus,
    };
    use litebox_broker_transport::shared_memory::SharedBufferPool;
    use rustix::io::FdFlags;
    use std::io::Write;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn mappings_share_bytes_and_validate_ranges() {
        let first = MemfdSharedMemory::create(64).unwrap();
        let second =
            MemfdSharedMemory::from_received_fd(first.fd.as_fd().try_clone_to_owned().unwrap(), 64)
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
        assert_eq!(
            second.load_u64_acquire(0),
            Err(SharedMemoryError::InvalidRange)
        );
    }

    #[test]
    fn mappings_preserve_disjoint_partial_word_writes() {
        let first = MemfdSharedMemory::create(10).unwrap();
        let second =
            MemfdSharedMemory::from_received_fd(first.fd.as_fd().try_clone_to_owned().unwrap(), 10)
                .unwrap();
        let start = Barrier::new(3);
        thread::scope(|scope| {
            scope.spawn(|| {
                start.wait();
                first.write(0, &[1; 4]).unwrap();
            });
            scope.spawn(|| {
                start.wait();
                second.write(4, &[2; 6]).unwrap();
            });
            start.wait();
        });

        let mut bytes = [0; 10];
        first.read(0, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 1, 1, 1, 2, 2, 2, 2, 2, 2]);
    }

    #[test]
    fn mappings_enforce_control_ring_typed_access() {
        let first = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let second = MemfdSharedMemory::from_received_fd(
            first.fd.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        let sequence_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_u64(*offset))
            .unwrap();
        let epoch_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_u32(*offset))
            .unwrap();
        let body_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_byte_range(*offset, 1))
            .unwrap();

        first
            .store_u64_release(sequence_offset, 0x0102_0304_0506_0708)
            .unwrap();
        assert_eq!(
            second.load_u64_acquire(sequence_offset),
            Ok(0x0102_0304_0506_0708)
        );
        assert_eq!(first.increment_u32_release(epoch_offset), Ok(()));
        assert_eq!(second.load_u32_acquire(epoch_offset), Ok(1));
        assert_eq!(
            first.store_u64_and_increment_u32_release(
                sequence_offset,
                0x1112_1314_1516_1718,
                epoch_offset,
            ),
            Ok(())
        );
        assert_eq!(
            second.load_u64_acquire(sequence_offset),
            Ok(0x1112_1314_1516_1718)
        );
        assert_eq!(second.load_u32_acquire(epoch_offset), Ok(2));
        second.write(body_offset, &[7]).unwrap();
        let mut byte = [0];
        first.read(body_offset, &mut byte).unwrap();
        assert_eq!(byte, [7]);

        assert_eq!(
            second.read(sequence_offset, &mut byte),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second.write(epoch_offset, &[0]),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second.load_u32_acquire(sequence_offset),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second.load_u64_acquire(body_offset),
            Err(SharedMemoryError::InvalidRange)
        );
        second.wait_while_equal(epoch_offset, 0).unwrap();
        assert_eq!(
            second.store_u64_and_increment_u32_release(sequence_offset, 0, sequence_offset),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second.load_u64_acquire(CONTROL_RING_MEMORY_SIZE),
            Err(SharedMemoryError::InvalidRange)
        );
        assert_eq!(
            second
                .wait_while_equal(sequence_offset, 0)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(
            second.wake_one(body_offset).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn futex_wait_returns_without_peer_cooperation() {
        let memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let epoch_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_u32(*offset))
            .unwrap();
        let start = Instant::now();

        memory.wait_while_equal(epoch_offset, 0).unwrap();

        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn peer_descriptor_writes_are_read_as_untrusted_snapshots() {
        let memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let peer_fd = memory.as_fd().try_clone_to_owned().unwrap();
        let sequence_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_u64(*offset))
            .unwrap();
        let epoch_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| memory_permits_u32(*offset))
            .unwrap();

        let mut expected_sequence = [0; size_of::<u64>()];
        expected_sequence[1..4].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(
            rustix::io::pwrite(
                &peer_fd,
                &expected_sequence[1..4],
                u64::try_from(sequence_offset).unwrap() + 1,
            ),
            Ok(3)
        );
        assert_eq!(
            memory.load_u64_acquire(sequence_offset),
            Ok(u64::from_ne_bytes(expected_sequence))
        );

        assert_eq!(
            rustix::io::pwrite(
                &peer_fd,
                &u32::MAX.to_ne_bytes(),
                u64::try_from(epoch_offset).unwrap(),
            ),
            Ok(size_of::<u32>())
        );
        memory.increment_u32_release(epoch_offset).unwrap();
        assert_eq!(memory.load_u32_acquire(epoch_offset), Ok(0));
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
            MemfdSharedMemory::from_received_fd(
                memory.fd.as_fd().try_clone_to_owned().unwrap(),
                32,
            )
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
    fn transfers_exact_pool_with_shared_visibility_and_close_on_exec() {
        let memory = MemfdSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
        let pool = SharedBufferPool::new(memory, SHARED_BUFFER_LAYOUT).unwrap();
        for index in 0..SHARED_BUFFER_LAYOUT.slot_count() {
            pool.write(
                SharedBufferSlotIndex(index),
                &[u8::try_from(index).unwrap()],
            )
            .unwrap();
        }
        let (mut local_stream, mut host_stream) = UnixStream::pair().unwrap();

        send_memfd(&mut host_stream, pool.memory(), None).unwrap();
        let mapped_memory =
            receive_memfd(&mut local_stream, SHARED_BUFFER_POOL_SIZE, None).unwrap();
        let mapped_pool = SharedBufferPool::new(mapped_memory, SHARED_BUFFER_LAYOUT).unwrap();
        for index in 0..SHARED_BUFFER_LAYOUT.slot_count() {
            let mut byte = [0];
            mapped_pool
                .read(SharedBufferSlotIndex(index), &mut byte)
                .unwrap();
            assert_eq!(byte, [u8::try_from(index).unwrap()]);
        }
        let flags = rustix::io::fcntl_getfd(mapped_pool.memory().fd.as_fd()).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn transfers_exact_sealed_control_ring_mapping() {
        let memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let ring = ControlRing::new(memory).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();

        send_memfd(&mut sender, ring.memory(), None).unwrap();
        let mapped = receive_memfd(&mut receiver, CONTROL_RING_MEMORY_SIZE, None).unwrap();
        let mapped_ring = ControlRing::new(mapped).unwrap();
        ring.memory().write(13, &[1, 2, 3]).unwrap();
        let mut bytes = [0; 3];
        mapped_ring.memory().read(13, &mut bytes).unwrap();
        assert_eq!(bytes, [1, 2, 3]);

        let flags = rustix::io::fcntl_getfd(mapped_ring.memory().fd.as_fd()).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
        let seals = fcntl_get_seals(mapped_ring.memory().fd.as_fd()).unwrap();
        assert!(seals.contains(REQUIRED_MEMFD_SEALS));
        assert!(!seals.contains(SealFlags::WRITE));
    }

    #[test]
    fn shared_futex_wakeup_prevents_missed_cross_mapping_work() {
        let local_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let broker_memory = MemfdSharedMemory::from_received_fd(
            local_memory.fd.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        let mut producer = ControlRing::new(local_memory)
            .unwrap()
            .into_local()
            .request_producer;
        let mut consumer = ControlRing::new(broker_memory)
            .unwrap()
            .into_broker()
            .request_consumer;
        let empty_checked = Arc::new(Barrier::new(2));
        let broker_empty_checked = Arc::clone(&empty_checked);

        let broker = thread::spawn(move || {
            let ControlRingReadStatus::Empty {
                wait_epoch: producer_epoch,
            } = consumer
                .try_read(|payload| Ok::<_, ()>(payload[0]))
                .unwrap()
            else {
                panic!("request ring should initially be empty");
            };
            broker_empty_checked.wait();
            consumer.wait_for_message(producer_epoch).unwrap();
            for expected in 0..CONTROL_RING_SLOT_COUNT {
                let expected = u8::try_from(expected).unwrap();
                loop {
                    match consumer
                        .try_read(|payload| Ok::<_, ()>(payload[0]))
                        .unwrap()
                    {
                        ControlRingReadStatus::Message(value) => {
                            assert_eq!(value, expected);
                            break;
                        }
                        ControlRingReadStatus::Empty { wait_epoch } => {
                            consumer.wait_for_message(wait_epoch).unwrap();
                        }
                    }
                }
            }

            consumer.publish_head().unwrap();
            consumer.wake_producer().unwrap();
            match consumer
                .try_read(|payload| Ok::<_, ()>(payload[0]))
                .unwrap()
            {
                ControlRingReadStatus::Empty { wait_epoch } => {
                    consumer.wait_for_message(wait_epoch).unwrap();
                    assert_eq!(
                        consumer.try_read(|payload| Ok::<_, ()>(payload[0])),
                        Ok(ControlRingReadStatus::Message(0xff))
                    );
                }
                ControlRingReadStatus::Message(value) => assert_eq!(value, 0xff),
            }
        });

        empty_checked.wait();
        for value in 0..CONTROL_RING_SLOT_COUNT {
            let value = u8::try_from(value).unwrap();
            assert_eq!(
                producer.try_write(&[value]),
                Ok(ControlRingWriteStatus::Written)
            );
        }
        let ControlRingWriteStatus::Full {
            wait_epoch: consumer_epoch,
        } = producer.try_write(&[0xff]).unwrap()
        else {
            panic!("request ring should be full");
        };
        producer.wake_consumer().unwrap();

        producer.wait_for_capacity(consumer_epoch).unwrap();
        assert_eq!(
            producer.try_write(&[0xff]),
            Ok(ControlRingWriteStatus::Written)
        );
        producer.wake_consumer().unwrap();

        broker.join().unwrap();
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
        send_test_fds(&mut sender, &[memory.fd.as_fd(), memory.fd.as_fd()]);
        assert_eq!(
            receive_memfd(&mut receiver, length, None)
                .err()
                .expect("multiple descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        let fd = memory.fd.as_fd();
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
        let length = SHARED_BUFFER_POOL_SIZE;

        let wrong_size = MemfdSharedMemory::create(length - 1).unwrap();
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
