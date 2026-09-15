// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fixed-size Darwin POSIX shared memory.
//!
//! Unlike an ordinary temporary file, Darwin POSIX shm can be sized only once:
//! XNU's pshm_truncate rejects an already allocated object with EINVAL. A runner
//! receiving the descriptor therefore cannot shrink a broker mapping and cause
//! SIGBUS. Names are unpredictable, mode 0600, and unlinked before transfer.
//!
//! As in the Windows transport, peer-writable memory is accessed through inline
//! assembly, never Rust references or Rust atomics. Even mixed-width malicious
//! peer writes cannot introduce Rust data races. Control words use AArch64
//! acquire/release instructions; byte copies return untrusted snapshots.

use std::arch::asm;
use std::ffi::CString;
use std::io::{Error, ErrorKind, Result as IoResult};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use std::time::Instant;

use crate::setup::invalid_data;
use crate::unix_io::{with_read_deadline, with_write_deadline};
use litebox_broker_transport::control_ring::{
    CONTROL_RING_MEMORY_SIZE, MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};

/// A stable shared mapping. Only the broker creates the backing objects.
pub struct MacosSharedMemory {
    fd: OwnedFd,
    address: NonNull<u8>,
    length: usize,
    policy: MemoryAccessPolicy,
}

// SAFETY: metadata is immutable, the mapping remains live until drop, and all
// peer-writable accesses use checked assembly operations, not Rust references.
unsafe impl Send for MacosSharedMemory {}
// SAFETY: same reasoning as Send; concurrent local word operations are atomic.
unsafe impl Sync for MacosSharedMemory {}

impl MacosSharedMemory {
    /// Creates a byte-copy pool with a fixed nonzero length.
    pub fn create(length: usize) -> IoResult<Self> {
        Self::create_with_policy(length, MemoryAccessPolicy::Bytes)
    }

    /// Creates fixed-size control-ring memory.
    pub fn create_control_ring() -> IoResult<Self> {
        Self::create_with_policy(CONTROL_RING_MEMORY_SIZE, MemoryAccessPolicy::ControlRing)
    }

    fn create_with_policy(length: usize, policy: MemoryAccessPolicy) -> IoResult<Self> {
        if length == 0 || length > isize::MAX as usize {
            return Err(invalid_data("invalid shared-memory length"));
        }
        let mut nonce = [0; 12];
        getrandom::fill(&mut nonce).map_err(|error| Error::other(error.to_string()))?;
        let name = CString::new(format!(
            "/lb-{:024x}",
            u128::from_le_bytes({
                let mut bytes = [0; 16];
                bytes[..12].copy_from_slice(&nonce);
                bytes
            })
        ))
        .unwrap();
        // SAFETY: name is a live NUL-terminated string. O_EXCL prevents opening
        // another process's object. shm_open sets FD_CLOEXEC on Darwin.
        let raw_fd = unsafe {
            libc::shm_open(
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                0o600,
            )
        };
        if raw_fd < 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: successful shm_open returns a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        // Unlink immediately, including before any fallible mapping operation.
        // SAFETY: name still identifies the object we exclusively created.
        if unsafe { libc::shm_unlink(name.as_ptr()) } != 0 {
            return Err(Error::last_os_error());
        }
        // SAFETY: fd is a newly created POSIX shm object, sized exactly once.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), length.try_into().unwrap()) } != 0 {
            return Err(Error::last_os_error());
        }
        Self::map(fd, length, policy)
    }

    /// Maps a pool descriptor received from the trusted broker.
    ///
    /// The runner trusts the broker. The broker never accepts descriptors from
    /// the runner and must only use `create` / `create_control_ring` above.
    pub fn from_received_fd(fd: OwnedFd, expected_length: usize) -> IoResult<Self> {
        Self::map(fd, expected_length, MemoryAccessPolicy::Bytes)
    }

    /// Maps a control-ring descriptor received from the trusted broker.
    pub fn control_ring_from_received_fd(fd: OwnedFd) -> IoResult<Self> {
        Self::map(
            fd,
            CONTROL_RING_MEMORY_SIZE,
            MemoryAccessPolicy::ControlRing,
        )
    }

    fn map(fd: OwnedFd, length: usize, policy: MemoryAccessPolicy) -> IoResult<Self> {
        if length == 0 || length > isize::MAX as usize {
            return Err(invalid_data("invalid shared-memory length"));
        }
        let stat = rustix::fs::fstat(&fd)?;
        // Darwin POSIX shm reports no file type. Reject ordinary resizable files.
        // Darwin rounds a POSIX shm allocation up to the native page size.
        // SAFETY: sysconf is a scalar query with no pointer arguments.
        let page_size = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| invalid_data("invalid host page size"))?;
        let backing_length = length
            .checked_next_multiple_of(page_size)
            .ok_or_else(|| invalid_data("shared-memory length overflow"))?;
        let backing_length = i64::try_from(backing_length)
            .map_err(|_| invalid_data("shared-memory length overflow"))?;
        if stat.st_mode & libc::S_IFMT != 0 || stat.st_size != backing_length {
            return Err(invalid_data(
                "expected fixed-size Darwin POSIX shared memory",
            ));
        }
        // SAFETY: checked length fits isize and matches the object size. Mapping
        // lifetime is owned by this value; Rust never dereferences its contents.
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
            address,
            length,
            policy,
        })
    }

    fn checked(
        &self,
        offset: usize,
        length: usize,
        alignment: usize,
    ) -> Result<*mut u8, SharedMemoryError> {
        if offset
            .checked_add(length)
            .is_none_or(|end| end > self.length)
        {
            return Err(SharedMemoryError::InvalidRange);
        }
        if !offset.is_multiple_of(alignment) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        Ok(self.address.as_ptr().wrapping_add(offset))
    }

    fn word32(&self, offset: usize) -> Result<*mut u8, SharedMemoryError> {
        if !self.policy.permits_u32(offset) {
            return Err(SharedMemoryError::InvalidRange);
        }
        self.checked(offset, 4, 4)
    }

    fn word64(&self, offset: usize) -> Result<*mut u8, SharedMemoryError> {
        if !self.policy.permits_u64(offset) {
            return Err(SharedMemoryError::InvalidRange);
        }
        self.checked(offset, 8, 8)
    }
}

impl Drop for MacosSharedMemory {
    fn drop(&mut self) {
        // SAFETY: this value owns this entire live mapping.
        unsafe { libc::munmap(self.address.as_ptr().cast(), self.length) };
    }
}

impl AsFd for MacosSharedMemory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// SAFETY requirements: source and destination are valid for length bytes and
// disjoint. One may refer to peer-writable memory. No Rust access to that memory
// occurs, and the assembly has a compiler memory clobber.
unsafe fn copy_bytes(source: *const u8, destination: *mut u8, length: usize) {
    if length == 0 {
        return;
    }
    unsafe {
        asm!(
            "2:",
            "ldrb {byte:w}, [{source}], #1",
            "strb {byte:w}, [{destination}], #1",
            "subs {length}, {length}, #1",
            "b.ne 2b",
            source = inout(reg) source => _,
            destination = inout(reg) destination => _,
            length = inout(reg) length => _,
            byte = out(reg) _,
            options(nostack),
        );
    }
}

impl SharedMemory for MacosSharedMemory {
    fn len(&self) -> usize {
        self.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = self.checked(offset, destination.len(), 1)?;
        if !self.policy.permits_byte_range(offset, destination.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        // SAFETY: the full source range was checked; destination is private Rust
        // storage and cannot alias the mapping, which exposes no references.
        unsafe { copy_bytes(source, destination.as_mut_ptr(), destination.len()) };
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = self.checked(offset, source.len(), 1)?;
        if !self.policy.permits_byte_range(offset, source.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        // SAFETY: the full destination range was checked and source is private.
        unsafe { copy_bytes(source.as_ptr(), destination, source.len()) };
        Ok(())
    }
}

impl ControlRingMemory for MacosSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = self.word32(offset)?;
        let value;
        // SAFETY: address is a live aligned u32 control word. LDAR is indivisible
        // and acquire-ordered, without forming a reference into peer memory.
        unsafe {
            asm!("ldar {value:w}, [{address}]", value = out(reg) value,
            address = in(reg) address, options(nostack, preserves_flags));
        }
        Ok(value)
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = self.word32(offset)?;
        // SAFETY: checked live aligned u32. The exclusive loop atomically wraps
        // and release-publishes the increment, including across processes.
        unsafe {
            asm!(
            "2:", "ldxr {value:w}, [{address}]", "add {value:w}, {value:w}, #1",
            "stlxr {status:w}, {value:w}, [{address}]", "cbnz {status:w}, 2b",
            address = in(reg) address, value = out(reg) _, status = out(reg) _,
            options(nostack, preserves_flags));
        }
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = self.word64(offset)?;
        let value;
        // SAFETY: checked live aligned u64, as above.
        unsafe {
            asm!("ldar {value}, [{address}]", value = out(reg) value,
            address = in(reg) address, options(nostack, preserves_flags));
        }
        Ok(value)
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = self.word64(offset)?;
        // SAFETY: checked live aligned u64. STLR is indivisible and release-ordered.
        unsafe {
            asm!("stlr {value}, [{address}]", value = in(reg) value,
            address = in(reg) address, options(nostack, preserves_flags));
        }
        Ok(())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        // Policies enforce disjoint byte/u32/u64 regions. Validate both before
        // modifying either, so invalid input cannot partially publish state.
        self.word64(store_offset)?;
        self.word32(increment_offset)?;
        self.store_u64_release(store_offset, value)?;
        self.increment_u32_release(increment_offset)
    }
}

// Public libSystem address-wait API, available on macOS 14.4+. Shared waits key
// on the backing object rather than each process's virtual mapping address.
unsafe extern "C" {
    fn os_sync_wait_on_address_with_timeout(
        address: *mut libc::c_void,
        value: u64,
        size: usize,
        flags: u32,
        clock: u32,
        timeout_ns: u64,
    ) -> i32;
    fn os_sync_wake_by_address_any(address: *mut libc::c_void, size: usize, flags: u32) -> i32;
}
const OS_SYNC_SHARED: u32 = 1;
const OS_CLOCK_MACH_ABSOLUTE_TIME: u32 = 32;

impl WaitableSharedMemory for MacosSharedMemory {
    type Error = Error;
    fn wait_access_error(error: SharedMemoryError) -> Error {
        Error::new(ErrorKind::InvalidInput, error)
    }

    fn wait_while_equal(&self, offset: usize, expected: u32) -> IoResult<()> {
        let address = self.word32(offset).map_err(Self::wait_access_error)?;
        // Fault in the page before the kernel's non-faulting copyin and avoid
        // sleeping if the caller's sampled epoch has already changed.
        if self
            .load_u32_acquire(offset)
            .map_err(Self::wait_access_error)?
            != expected
        {
            return Ok(());
        }
        // SAFETY: address is a checked aligned word within the stable mapping.
        // Bounded waits let endpoints recheck trusted cancellation state even
        // when a hostile peer restores the shared epoch after cancellation.
        let result = unsafe {
            os_sync_wait_on_address_with_timeout(
                address.cast(),
                u64::from(expected),
                4,
                OS_SYNC_SHARED,
                OS_CLOCK_MACH_ABSOLUTE_TIME,
                100_000_000,
            )
        };
        if result >= 0 {
            return Ok(());
        }
        let error = Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR | libc::ETIMEDOUT | libc::EAGAIN | libc::EFAULT | libc::ENOMEM) => {
                Ok(())
            }
            _ => Err(error),
        }
    }

    fn wake_one(&self, offset: usize) -> IoResult<()> {
        let address = self.word32(offset).map_err(Self::wait_access_error)?;
        // SAFETY: address is a checked aligned word within the stable mapping.
        let result = unsafe { os_sync_wake_by_address_any(address.cast(), 4, OS_SYNC_SHARED) };
        if result == 0 {
            return Ok(());
        }
        let error = Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests;

/// Sends a broker-created mapping during exclusive setup.
pub fn send_shared_memory(
    stream: &mut UnixStream,
    memory: &MacosSharedMemory,
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        crate::fd_transfer::send_fd(stream, memory.as_fd(), deadline)
    })
}

/// Receives a pool mapping from the trusted broker during exclusive setup.
pub fn receive_shared_memory(
    stream: &mut UnixStream,
    expected_length: usize,
    deadline: Option<Instant>,
) -> IoResult<MacosSharedMemory> {
    let fd = with_read_deadline(stream, deadline, crate::fd_transfer::receive_fd)?;
    MacosSharedMemory::from_received_fd(fd, expected_length)
}

/// Receives a control-ring mapping from the trusted broker during exclusive setup.
pub fn receive_control_ring(
    stream: &mut UnixStream,
    deadline: Option<Instant>,
) -> IoResult<MacosSharedMemory> {
    let fd = with_read_deadline(stream, deadline, crate::fd_transfer::receive_fd)?;
    MacosSharedMemory::control_ring_from_received_fd(fd)
}
