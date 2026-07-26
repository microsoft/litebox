// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux memfd-backed association shared memory.
//!
//! One sealed memfd mapping backs an association shared-buffer pool or a shared
//! control ring. The mapping implements the portable shared-memory interfaces in
//! `litebox_broker_transport`, and its futex support lets portable control-ring
//! endpoints block and wake without knowing anything about Linux.

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
use rustix::io::Errno;
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use rustix::thread::futex;

use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_LAYOUT, CONTROL_RING_MEMORY_SIZE, WaitableSharedMemory,
};
use litebox_broker_transport::shared_memory::{
    AtomicSharedMemory, SharedMemory, SharedMemoryError,
};

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

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
    access: MemoryAccessPolicy,
}

struct MappedRegion {
    address: NonNull<u8>,
    length: usize,
}

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
            Self::ControlRing => CONTROL_RING_MEMORY_LAYOUT.permits_byte_range(offset, length),
        }
    }

    const fn permits_atomic_u32(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing => CONTROL_RING_MEMORY_LAYOUT.permits_atomic_u32(offset),
        }
    }

    const fn permits_atomic_u64(self, offset: usize) -> bool {
        match self {
            Self::Bytes => false,
            Self::ControlRing => CONTROL_RING_MEMORY_LAYOUT.permits_atomic_u64(offset),
        }
    }
}

// SAFETY: Moving or sharing this owner does not move or invalidate its OS
// mapping. Its metadata is immutable, and contents are accessed through a fixed
// atomic representation without exposing references to callers.
unsafe impl Send for MappedRegion {}
// SAFETY: See the `Send` justification. Concurrent content access uses atomics.
unsafe impl Sync for MappedRegion {}

fn atomic_u64_at(
    memory: &MemfdSharedMemory,
    offset: usize,
) -> Result<&AtomicU64, SharedMemoryError> {
    if !memory.access.permits_atomic_u64(offset) {
        return Err(SharedMemoryError::InvalidRange);
    }
    let byte_address = shared_address(
        &memory.mapping,
        offset,
        size_of::<u64>(),
        align_of::<AtomicU64>(),
    )?;
    // The runtime check above establishes the stronger alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let address = byte_address.cast::<u64>();
    // SAFETY: The pointer is valid and aligned for a `u64`. Control-ring
    // sequence words are accessed atomically by conforming endpoints, and
    // `memory` keeps the immutable mapping alive for the returned reference.
    Ok(unsafe { AtomicU64::from_ptr(address) })
}

fn atomic_u32_at(
    memory: &MemfdSharedMemory,
    offset: usize,
) -> Result<&AtomicU32, SharedMemoryError> {
    if !memory.access.permits_atomic_u32(offset) {
        return Err(SharedMemoryError::InvalidRange);
    }
    let byte_address = shared_address(
        &memory.mapping,
        offset,
        size_of::<u32>(),
        align_of::<AtomicU32>(),
    )?;
    // The runtime check above establishes the stronger alignment.
    #[allow(clippy::cast_ptr_alignment)]
    let address = byte_address.cast::<u32>();
    // SAFETY: The pointer is valid and aligned for a `u32`. Control-ring epoch
    // words are accessed atomically by conforming endpoints and the futex
    // syscall, and `memory` keeps the immutable mapping alive for the returned
    // reference.
    Ok(unsafe { AtomicU32::from_ptr(address) })
}

fn shared_address(
    mapping: &MappedRegion,
    offset: usize,
    size: usize,
    alignment: usize,
) -> Result<*mut u8, SharedMemoryError> {
    offset
        .checked_add(size)
        .filter(|end| *end <= mapping.length)
        .ok_or(SharedMemoryError::InvalidRange)?;
    // SAFETY: The checked offset is inside the live mapping.
    let byte_address = unsafe { mapping.address.as_ptr().add(offset) };
    if !byte_address.addr().is_multiple_of(alignment) {
        return Err(SharedMemoryError::UnalignedAtomic);
    }
    Ok(byte_address)
}

fn atomic_word_at(mapping: &MappedRegion, offset: usize) -> Result<&AtomicU64, SharedMemoryError> {
    let address = shared_address(mapping, offset, size_of::<u64>(), align_of::<AtomicU64>())?;
    // SAFETY: The checked address is valid and aligned for one word, the mapping
    // stays live for the returned reference, and every full word in a byte
    // region uses this same atomic representation.
    Ok(unsafe { AtomicU64::from_ptr(address.cast()) })
}

fn atomic_byte_at(mapping: &MappedRegion, offset: usize) -> Result<&AtomicU8, SharedMemoryError> {
    let address = shared_address(mapping, offset, size_of::<u8>(), align_of::<AtomicU8>())?;
    // SAFETY: The checked address is valid and aligned for one byte, the mapping
    // stays live for the returned reference, and only a trailing partial word
    // uses this byte representation.
    Ok(unsafe { AtomicU8::from_ptr(address) })
}

fn read_atomic_bytes(
    mapping: &MappedRegion,
    offset: usize,
    destination: &mut [u8],
) -> Result<(), SharedMemoryError> {
    shared_address(mapping, offset, destination.len(), align_of::<AtomicU8>())?;
    let mut copied = 0;
    while copied < destination.len() {
        let absolute = offset + copied;
        let word_start = absolute - absolute % size_of::<u64>();
        if word_start + size_of::<u64>() <= mapping.length {
            let word = atomic_word_at(mapping, word_start)?
                .load(Ordering::Relaxed)
                .to_ne_bytes();
            let word_offset = absolute - word_start;
            let count = (size_of::<u64>() - word_offset).min(destination.len() - copied);
            destination[copied..copied + count]
                .copy_from_slice(&word[word_offset..word_offset + count]);
            copied += count;
        } else {
            destination[copied] = atomic_byte_at(mapping, absolute)?.load(Ordering::Relaxed);
            copied += 1;
        }
    }
    Ok(())
}

fn write_atomic_bytes(
    mapping: &MappedRegion,
    offset: usize,
    source: &[u8],
) -> Result<(), SharedMemoryError> {
    shared_address(mapping, offset, source.len(), align_of::<AtomicU8>())?;
    let mut copied = 0;
    while copied < source.len() {
        let absolute = offset + copied;
        let word_start = absolute - absolute % size_of::<u64>();
        if word_start + size_of::<u64>() <= mapping.length {
            let word = atomic_word_at(mapping, word_start)?;
            let word_offset = absolute - word_start;
            let count = (size_of::<u64>() - word_offset).min(source.len() - copied);
            if word_offset == 0 && count == size_of::<u64>() {
                word.store(
                    u64::from_ne_bytes(
                        source[copied..copied + count]
                            .try_into()
                            .expect("full atomic word"),
                    ),
                    Ordering::Relaxed,
                );
            } else {
                let mut current = word.load(Ordering::Relaxed);
                loop {
                    let mut updated = current.to_ne_bytes();
                    updated[word_offset..word_offset + count]
                        .copy_from_slice(&source[copied..copied + count]);
                    match word.compare_exchange_weak(
                        current,
                        u64::from_ne_bytes(updated),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(observed) => current = observed,
                    }
                }
            }
            copied += count;
        } else {
            atomic_byte_at(mapping, absolute)?.store(source[copied], Ordering::Relaxed);
            copied += 1;
        }
    }
    Ok(())
}

fn validate_nonoverlapping_atomic_ranges(
    store_offset: usize,
    add_offset: usize,
) -> Result<(), SharedMemoryError> {
    let store_end = store_offset
        .checked_add(size_of::<u64>())
        .ok_or(SharedMemoryError::InvalidRange)?;
    let add_end = add_offset
        .checked_add(size_of::<u32>())
        .ok_or(SharedMemoryError::InvalidRange)?;
    if store_offset < add_end && add_offset < store_end {
        return Err(SharedMemoryError::InvalidRange);
    }
    Ok(())
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
            access: MemoryAccessPolicy::for_length(length),
        })
    }
}

impl WaitableSharedMemory for MemfdSharedMemory {
    type Error = Error;

    fn wait_access_error(error: SharedMemoryError) -> Error {
        Error::new(ErrorKind::InvalidInput, error)
    }

    /// Waits while a shared atomic `u32` still equals `expected`.
    ///
    /// A value change or signal interruption is reported as a successful,
    /// possibly spurious wakeup. The caller must recheck its wait condition.
    fn wait_while_equal(&self, offset: usize, expected: u32) -> IoResult<()> {
        let word = atomic_u32_at(self, offset).map_err(Self::wait_access_error)?;
        match futex::wait(word, futex::Flags::empty(), expected, None) {
            Ok(()) | Err(Errno::AGAIN | Errno::INTR) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Wakes one waiter blocked on a shared atomic `u32`.
    fn wake_one(&self, offset: usize) -> IoResult<()> {
        let word = atomic_u32_at(self, offset).map_err(Self::wait_access_error)?;
        futex::wake(word, futex::Flags::empty(), 1)?;
        Ok(())
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
        shared_address(
            &self.mapping,
            offset,
            destination.len(),
            align_of::<AtomicU8>(),
        )?;
        if !self.access.permits_byte_range(offset, destination.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        read_atomic_bytes(&self.mapping, offset, destination)
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        shared_address(&self.mapping, offset, source.len(), align_of::<AtomicU8>())?;
        if !self.access.permits_byte_range(offset, source.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        write_atomic_bytes(&self.mapping, offset, source)
    }
}

impl AtomicSharedMemory for MemfdSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        Ok(atomic_u32_at(self, offset)?.load(Ordering::Acquire))
    }

    fn fetch_add_u32_release(&self, offset: usize, value: u32) -> Result<u32, SharedMemoryError> {
        Ok(atomic_u32_at(self, offset)?.fetch_add(value, Ordering::Release))
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        Ok(atomic_u64_at(self, offset)?.load(Ordering::Acquire))
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        atomic_u64_at(self, offset)?.store(value, Ordering::Release);
        Ok(())
    }

    fn store_u64_and_fetch_add_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        add_offset: usize,
        add_value: u32,
    ) -> Result<u32, SharedMemoryError> {
        validate_nonoverlapping_atomic_ranges(store_offset, add_offset)?;
        let stored = atomic_u64_at(self, store_offset)?;
        let added = atomic_u32_at(self, add_offset)?;
        stored.store(value, Ordering::Release);
        Ok(added.fetch_add(add_value, Ordering::Release))
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
        assert_eq!(
            second.load_u64_acquire(0),
            Err(SharedMemoryError::InvalidRange)
        );
    }

    #[test]
    fn mappings_preserve_disjoint_partial_word_writes() {
        let first = MemfdSharedMemory::create(10).unwrap();
        let second =
            MemfdSharedMemory::from_received_fd(first.as_fd().try_clone_to_owned().unwrap(), 10)
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
            first.as_fd().try_clone_to_owned().unwrap(),
            CONTROL_RING_MEMORY_SIZE,
        )
        .unwrap();
        let sequence_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| CONTROL_RING_MEMORY_LAYOUT.permits_atomic_u64(*offset))
            .unwrap();
        let epoch_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| CONTROL_RING_MEMORY_LAYOUT.permits_atomic_u32(*offset))
            .unwrap();
        let body_offset = (0..CONTROL_RING_MEMORY_SIZE)
            .find(|offset| CONTROL_RING_MEMORY_LAYOUT.permits_byte_range(*offset, 1))
            .unwrap();

        first
            .store_u64_release(sequence_offset, 0x0102_0304_0506_0708)
            .unwrap();
        assert_eq!(
            second.load_u64_acquire(sequence_offset),
            Ok(0x0102_0304_0506_0708)
        );
        assert_eq!(first.fetch_add_u32_release(epoch_offset, 3), Ok(0));
        assert_eq!(second.load_u32_acquire(epoch_offset), Ok(3));
        assert_eq!(
            first.store_u64_and_fetch_add_u32_release(
                sequence_offset,
                0x1112_1314_1516_1718,
                epoch_offset,
                2
            ),
            Ok(3)
        );
        assert_eq!(
            second.load_u64_acquire(sequence_offset),
            Ok(0x1112_1314_1516_1718)
        );
        assert_eq!(second.load_u32_acquire(epoch_offset), Ok(5));
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
            second.store_u64_and_fetch_add_u32_release(sequence_offset, 0, sequence_offset, 1),
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
        let flags = rustix::io::fcntl_getfd(mapped_pool.memory().as_fd()).unwrap();
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

        let flags = rustix::io::fcntl_getfd(mapped_ring.memory().as_fd()).unwrap();
        assert!(flags.contains(FdFlags::CLOEXEC));
        let seals = fcntl_get_seals(mapped_ring.memory().as_fd()).unwrap();
        assert!(seals.contains(REQUIRED_MEMFD_SEALS));
        assert!(!seals.contains(SealFlags::WRITE));
    }

    #[test]
    fn shared_futex_wakeup_prevents_missed_cross_mapping_work() {
        let local_memory = MemfdSharedMemory::create(CONTROL_RING_MEMORY_SIZE).unwrap();
        let broker_memory = MemfdSharedMemory::from_received_fd(
            local_memory.as_fd().try_clone_to_owned().unwrap(),
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
                assert_eq!(
                    consumer.try_read(|payload| Ok::<_, ()>(payload[0])),
                    Ok(ControlRingReadStatus::Message(expected))
                );
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
