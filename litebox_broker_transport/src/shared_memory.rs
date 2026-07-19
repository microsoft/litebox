// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Reusable Linux memfd-backed shared memory.

use std::io::{Error, Result as IoResult};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::Mutex;

use rustix::fs::{
    MemfdFlags, SealFlags, fcntl_add_seals, fcntl_get_seals, fstat, ftruncate, memfd_create,
};

use litebox_broker_protocol::shared_memory::{SharedMemory, SharedMemoryError};

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
}
