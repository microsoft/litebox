// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! macOS POSIX-shared-memory-backed broker association memory.
//!
//! One POSIX shared-memory mapping backs an association shared-buffer pool or
//! a shared control ring. The mapping implements the portable shared-memory
//! interfaces in `litebox_broker_transport`, and its `os_sync_wait_on_address`
//! support lets portable control-ring endpoints block and wake across
//! processes without knowing anything about macOS.
//!
//! Rust never forms references into the peer-writable mapping. Byte and word
//! access goes through [`peer_memory`], which copies untrusted snapshots into
//! private buffers, and waits and wakes hand checked addresses to the kernel.
//!
//! Direct access raises `SIGBUS` instead of returning an error if a mapped page
//! loses its backing, so every mapping must have a size nobody can change.
//! macOS has no memfd seals, but a POSIX shared-memory object accepts exactly
//! one `ftruncate` (later ones fail with `EINVAL`, even for its creator), so
//! sizing each object once at creation fixes its size. The broker maps only
//! objects it created, never one its peer created and sized. Runners receive
//! descriptors only from the trusted broker and map them at the protocol's
//! expected sizes without re-inspecting them.

use std::fmt::Write as _;
use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Result as IoResult};
use std::mem::{align_of, size_of};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use rustix::fs::ftruncate;
use rustix::io::{Errno, FdFlags, fcntl_setfd};
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags,
};
use rustix::shm;

use litebox_broker_transport::control_ring::{
    CONTROL_RING_PARALLEL_SPIN_LIMIT, ControlRingLayout, MemoryAccessPolicy, WaitableSharedMemory,
};
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_platform::buffer::RawBytes;
use litebox_platform::peer_memory;

use crate::setup::invalid_data;
use crate::unix_io::{
    refresh_read_deadline, refresh_write_deadline, with_read_deadline, with_write_deadline,
};

/// `VM_INHERIT_NONE` from `<mach/vm_inherit.h>`, which `libc` does not expose.
const VM_INHERIT_NONE: libc::c_int = 2;

unsafe extern "C" {
    /// `minherit(2)` from `<sys/mman.h>`, which `libc` does not expose.
    fn minherit(
        address: *mut libc::c_void,
        length: libc::size_t,
        inheritance: libc::c_int,
    ) -> libc::c_int;
}

/// Bound on one shared wait, after which the waiter rechecks its condition.
const SHARED_WAIT_RECHECK_TIMEOUT: Duration = Duration::from_millis(100);

/// macOS POSIX-shared-memory-backed memory usable by broker transports.
pub struct MacosSharedMemory {
    fd: OwnedFd,
    mapping: MappedRegion,
    policy: MemoryAccessPolicy,
    spin_limit: u32,
}

struct MappedRegion {
    address: NonNull<u8>,
    length: usize,
}

// SAFETY: Moving or sharing this owner does not move or invalidate its OS
// mapping. Its metadata is immutable, and mapped contents are only accessed
// through `peer_memory` or the kernel, never through Rust references.
unsafe impl Send for MappedRegion {}
// SAFETY: See the `Send` justification. Every access derives a checked raw
// address from the mapping.
unsafe impl Sync for MappedRegion {}

fn checked_u64_address(
    memory: &MacosSharedMemory,
    offset: usize,
) -> Result<*mut u64, SharedMemoryError> {
    if !memory.policy.permits_u64(offset) {
        return Err(SharedMemoryError::InvalidRange);
    }
    let byte_address =
        shared_address(&memory.mapping, offset, size_of::<u64>(), align_of::<u64>())?;
    // The runtime check above establishes the required alignment.
    #[allow(clippy::cast_ptr_alignment)]
    Ok(byte_address.cast::<u64>())
}

fn checked_u32_address(
    memory: &MacosSharedMemory,
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

/// Blocks while the shared `u32` at `address` equals `expected`, for at most
/// `timeout`.
///
/// The shared flag keys the wait by the backing memory object rather than the
/// virtual address, so a wake through any mapping of the object, in any
/// process, reaches it. The kernel reads the value itself, keeping Rust
/// references out of memory a peer can modify, but it does not fault the page
/// in: a word on a page that was never touched fails with `EFAULT`.
fn shared_wait(address: *mut u32, expected: u32, timeout: Duration) -> IoResult<()> {
    let timeout_ns = u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX);
    // SAFETY: `address` is aligned and lies within a live shared mapping, and
    // `size` matches the `u32` it identifies.
    let result = unsafe {
        libc::os_sync_wait_on_address_with_timeout(
            address.cast(),
            u64::from(expected),
            size_of::<u32>(),
            libc::OS_SYNC_WAIT_ON_ADDRESS_SHARED,
            libc::OS_CLOCK_MACH_ABSOLUTE_TIME,
            timeout_ns,
        )
    };
    if result < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Wakes one waiter blocked on the shared `u32` at `address`, returning
/// whether one was waiting.
fn shared_wake_one(address: *mut u32) -> IoResult<bool> {
    // SAFETY: `address` is aligned and lies within a live shared mapping, and
    // `size` matches the `u32` it identifies.
    let result = unsafe {
        libc::os_sync_wake_by_address_any(
            address.cast(),
            size_of::<u32>(),
            libc::OS_SYNC_WAKE_BY_ADDRESS_SHARED,
        )
    };
    if result == 0 {
        return Ok(true);
    }
    let error = Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error)
    }
}

impl MacosSharedMemory {
    /// Creates and maps fixed-size byte-copy shared memory with `length` bytes.
    pub fn create(length: usize) -> IoResult<Self> {
        Self::create_with_policy(length, MemoryAccessPolicy::Bytes)
    }

    /// Creates and maps fixed-size shared memory for one control ring with `layout`.
    pub fn create_control_ring(layout: ControlRingLayout) -> IoResult<Self> {
        Self::create_with_policy(
            layout.memory_size(),
            MemoryAccessPolicy::ControlRing(layout),
        )
    }

    /// Creates an anonymous POSIX shared-memory object of `length` bytes.
    ///
    /// macOS has no anonymous shared-memory descriptor, so the object is
    /// created under a random name and unlinked at once. The name is visible
    /// only for that moment, and the owner-only mode limits it to this user,
    /// who could already inspect this process. `O_EXCL` rejects a name another
    /// process created first.
    fn create_with_policy(length: usize, policy: MemoryAccessPolicy) -> IoResult<Self> {
        if length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        let size = length
            .try_into()
            .map_err(|_| invalid_data("shared-memory length exceeds u64"))?;
        let fd = loop {
            let mut random = [0u8; size_of::<u64>()];
            // SAFETY: `random` is writable for its whole length.
            unsafe { libc::arc4random_buf(random.as_mut_ptr().cast(), random.len()) };
            // `/litebox-` and 16 hex digits fit the 31-byte `PSHMNAMLEN` limit.
            let mut name = String::from("/litebox-");
            write!(name, "{:016x}", u64::from_ne_bytes(random)).expect("writing to a String");
            match shm::open(
                name.as_str(),
                shm::OFlags::CREATE | shm::OFlags::EXCL | shm::OFlags::RDWR,
                shm::Mode::RUSR | shm::Mode::WUSR,
            ) {
                Ok(fd) => {
                    shm::unlink(name.as_str())?;
                    break fd;
                }
                Err(Errno::EXIST) => {}
                Err(error) => return Err(error.into()),
            }
        };
        fcntl_setfd(&fd, FdFlags::CLOEXEC)?;
        // This first `ftruncate` is the only one the object accepts, so the
        // size is fixed from here on.
        ftruncate(&fd, size)?;
        Self::map(fd, length, policy)
    }

    /// Maps byte-copy shared memory received from the broker with
    /// `expected_length` bytes.
    ///
    /// The trusted broker creates the descriptor with that nonzero size fixed,
    /// so it is not re-inspected.
    pub fn from_received_fd(fd: OwnedFd, expected_length: usize) -> IoResult<Self> {
        Self::from_received_fd_with_policy(fd, expected_length, MemoryAccessPolicy::Bytes)
    }

    /// Maps control-ring shared memory with `layout` received from the broker.
    pub fn control_ring_from_received_fd(fd: OwnedFd, layout: ControlRingLayout) -> IoResult<Self> {
        Self::from_received_fd_with_policy(
            fd,
            layout.memory_size(),
            MemoryAccessPolicy::ControlRing(layout),
        )
    }

    fn from_received_fd_with_policy(
        fd: OwnedFd,
        expected_length: usize,
        policy: MemoryAccessPolicy,
    ) -> IoResult<Self> {
        if expected_length == 0 {
            return Err(invalid_data("shared memory cannot be empty"));
        }
        Self::map(fd, expected_length, policy)
    }

    fn map(fd: OwnedFd, length: usize, policy: MemoryAccessPolicy) -> IoResult<Self> {
        if length > isize::MAX as usize {
            return Err(invalid_data(
                "shared-memory length exceeds pointer offset range",
            ));
        }
        // SAFETY: `fd` refers to an object at least `length` bytes long. A null
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
        let mapping = MappedRegion { address, length };
        // A forked child must not inherit, and so cannot observe or corrupt,
        // its parent's association memory.
        // SAFETY: The range is exactly the mapping created above and owned by
        // `mapping`, and `VM_INHERIT_NONE` only affects inheritance by child
        // processes, not the range's contents or validity in this process.
        if unsafe { minherit(address.as_ptr().cast(), length, VM_INHERIT_NONE) } != 0 {
            return Err(Error::last_os_error());
        }
        let spin_limit = match policy {
            MemoryAccessPolicy::Bytes => 0,
            MemoryAccessPolicy::ControlRing(_) => parallel_spin_limit(),
        };
        Ok(Self {
            fd,
            mapping,
            policy,
            spin_limit,
        })
    }
}

/// [`CONTROL_RING_PARALLEL_SPIN_LIMIT`] if this process can run on more than
/// one CPU, so its ring peer may run in parallel.
fn parallel_spin_limit() -> u32 {
    match std::thread::available_parallelism() {
        Ok(parallelism) if parallelism.get() > 1 => CONTROL_RING_PARALLEL_SPIN_LIMIT,
        _ => 0,
    }
}

impl WaitableSharedMemory for MacosSharedMemory {
    type Error = Error;

    fn wait_access_error(error: SharedMemoryError) -> Error {
        Error::new(ErrorKind::InvalidInput, error)
    }

    /// Waits while a shared `u32` still equals `expected`.
    ///
    /// A value change, signal interruption, or documented transient failure is
    /// reported as a successful, possibly spurious wakeup. That includes
    /// `EFAULT` for a page not yet resident, which the caller's recheck faults
    /// in. A bounded wait also lets callers recheck trusted cancellation state
    /// if a hostile peer restores the sampled shared value after cancellation.
    /// The caller must recheck its wait condition.
    fn wait_while_equal(&self, offset: usize, expected: u32) -> IoResult<()> {
        let address = checked_u32_address(self, offset).map_err(Self::wait_access_error)?;
        match shared_wait(address, expected, SHARED_WAIT_RECHECK_TIMEOUT) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ETIMEDOUT | libc::EINTR | libc::EFAULT | libc::ENOMEM)
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
        shared_wake_one(address).map(drop)
    }

    fn spin_limit(&self) -> u32 {
        self.spin_limit
    }
}

impl AsFd for MacosSharedMemory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl SharedMemory for MacosSharedMemory {
    fn len(&self) -> usize {
        self.mapping.length
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = shared_address(&self.mapping, offset, destination.len(), 1)?;
        if !self.policy.permits_byte_range(offset, destination.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        // SAFETY: The range lies within the live mapping, which cannot overlap
        // the private destination.
        unsafe { peer_memory::copy_from_peer(source, destination) };
        Ok(())
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = shared_address(&self.mapping, offset, source.len(), 1)?;
        if !self.policy.permits_byte_range(offset, source.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        // SAFETY: The range lies within the live mapping, which cannot overlap
        // the private source.
        unsafe { peer_memory::copy_to_peer(source, destination) };
        Ok(())
    }

    fn raw_bytes(&self) -> Option<RawBytes<'_>> {
        if self.policy != MemoryAccessPolicy::Bytes {
            return None;
        }
        // SAFETY: The mapping lives as long as `self`, cannot be truncated
        // because the object's size was fixed when it was created, and is never
        // referenced.
        Some(unsafe { RawBytes::from_raw_parts(self.mapping.address, self.mapping.length) })
    }
}

impl ControlRingMemory for MacosSharedMemory {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = checked_u32_address(self, offset)?;
        // SAFETY: The address is aligned and lies within the live mapping.
        Ok(unsafe { peer_memory::load_u32_acquire(address) })
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = checked_u32_address(self, offset)?;
        // SAFETY: The address is aligned and lies within the live mapping.
        unsafe { peer_memory::increment_u32_release(address) };
        Ok(())
    }

    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
        let address = checked_u32_address(self, offset)?;
        // SAFETY: The address is aligned and lies within the live mapping.
        unsafe { peer_memory::store_u32_release(address, value) };
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = checked_u64_address(self, offset)?;
        // SAFETY: The address is aligned and lies within the live mapping.
        Ok(unsafe { peer_memory::load_u64_acquire(address) })
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = checked_u64_address(self, offset)?;
        // SAFETY: The address is aligned and lies within the live mapping.
        unsafe { peer_memory::store_u64_release(address, value) };
        Ok(())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        validate_nonoverlapping_word_ranges(store_offset, increment_offset)?;
        let store_address = checked_u64_address(self, store_offset)?;
        let increment_address = checked_u32_address(self, increment_offset)?;
        // SAFETY: Both addresses are aligned and lie within the live mapping.
        unsafe {
            peer_memory::store_u64_release(store_address, value);
            peer_memory::increment_u32_release(increment_address);
        }
        Ok(())
    }
}

/// Sends one shared-memory resource over an exclusively owned connected Unix
/// stream.
///
/// `deadline` bounds setup I/O without leaving a changed socket timeout behind.
pub fn send_shared_memory(
    stream: &mut UnixStream,
    memory: &MacosSharedMemory,
    deadline: Option<Instant>,
) -> IoResult<()> {
    with_write_deadline(stream, deadline, |stream, deadline| {
        send_fd(stream, memory.fd.as_fd(), deadline)
    })
}

/// Receives and maps one byte-copy shared-memory resource from the broker.
///
/// `expected_length` supplies the trusted expected size. `deadline` bounds
/// setup I/O without leaving a changed socket timeout behind.
pub fn receive_shared_memory(
    stream: &mut UnixStream,
    expected_length: usize,
    deadline: Option<Instant>,
) -> IoResult<MacosSharedMemory> {
    let fd = with_read_deadline(stream, deadline, receive_fd)?;
    MacosSharedMemory::from_received_fd(fd, expected_length)
}

/// Receives and maps one control-ring shared-memory resource with `layout`
/// from the broker.
pub fn receive_control_ring(
    stream: &mut UnixStream,
    layout: ControlRingLayout,
    deadline: Option<Instant>,
) -> IoResult<MacosSharedMemory> {
    let fd = with_read_deadline(stream, deadline, receive_fd)?;
    MacosSharedMemory::control_ring_from_received_fd(fd, layout)
}

/// Sends one setup frame: a carrier byte with `fd` attached.
///
/// macOS has no `MSG_NOSIGNAL`. The sockets this crate sends on come from
/// `std`, which sets `SO_NOSIGPIPE` on connected and accepted sockets, so a
/// closed peer is reported as `EPIPE`.
fn send_fd(stream: &mut UnixStream, fd: BorrowedFd<'_>, deadline: Option<Instant>) -> IoResult<()> {
    // Unix streams require an ordinary data byte to carry ancillary data.
    let carrier = [1];
    let io = [IoSlice::new(&carrier)];
    let fds = [fd];
    let mut control_space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(1)) }>();
    let mut control = SendAncillaryBuffer::new(&mut control_space);
    assert!(
        control.push(SendAncillaryMessage::ScmRights(&fds)),
        "SCM_RIGHTS control buffer is correctly sized"
    );
    loop {
        refresh_write_deadline(stream, deadline)?;
        match rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::empty()) {
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

/// Receives one setup frame's carrier byte and exactly one descriptor.
///
/// macOS has no `MSG_CMSG_CLOEXEC`, so the received descriptor is marked
/// close-on-exec right after `recvmsg`. Until then, a concurrent `fork` and
/// `exec` in another thread of this process could inherit it.
fn receive_fd(stream: &mut UnixStream, deadline: Option<Instant>) -> IoResult<OwnedFd> {
    let mut carrier = [0];
    let mut io = [IoSliceMut::new(&mut carrier)];
    let mut control_space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(4)) }>();
    let mut control = RecvAncillaryBuffer::new(&mut control_space);
    let received = loop {
        refresh_read_deadline(stream, deadline)?;
        match rustix::net::recvmsg(stream.as_fd(), &mut io, &mut control, RecvFlags::empty()) {
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
    for fd in &received_fds {
        fcntl_setfd(fd, FdFlags::CLOEXEC)?;
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
    Ok(received_fds.pop().expect("exactly one descriptor"))
}

impl Drop for MappedRegion {
    fn drop(&mut self) {
        // SAFETY: `address` and `length` describe the mapping exclusively owned
        // by this value, and it is unmapped exactly once here.
        let result = unsafe { munmap(self.address.as_ptr().cast(), self.length) };
        debug_assert!(result.is_ok(), "failed to unmap broker shared memory");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    const LAYOUT: ControlRingLayout = ControlRingLayout::MULTI_LANE;
    const MEMORY_SIZE: usize = LAYOUT.memory_size();

    fn first_u64_offset() -> usize {
        (0..MEMORY_SIZE)
            .find(|offset| LAYOUT.permits_u64(*offset))
            .unwrap()
    }

    fn first_u32_offset() -> usize {
        (0..MEMORY_SIZE)
            .find(|offset| LAYOUT.permits_u32(*offset))
            .unwrap()
    }

    fn alias(memory: &MacosSharedMemory) -> OwnedFd {
        memory.fd.as_fd().try_clone_to_owned().unwrap()
    }

    /// Forks a child that runs `child` and exits with its result, returning
    /// the child's PID.
    ///
    /// `child` runs in a copy of a multithreaded process, so it must make only
    /// async-signal-safe calls and must not allocate.
    fn fork_child(child: impl FnOnce() -> libc::c_int) -> libc::pid_t {
        // SAFETY: The child runs only `child`, which the caller restricts to
        // async-signal-safe calls, then leaves through `_exit`.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", Error::last_os_error());
        if pid == 0 {
            let code = child();
            // SAFETY: `_exit` skips Rust and libc teardown, which is unsafe in
            // a forked child.
            unsafe { libc::_exit(code) };
        }
        pid
    }

    fn child_exit_code(pid: libc::pid_t) -> libc::c_int {
        let mut status = 0;
        // SAFETY: `pid` is this process's unreaped child and `status` is writable.
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status {status:#x}");
        libc::WEXITSTATUS(status)
    }

    /// Returns whether `[address, address + length)` is still mapped in a
    /// forked child.
    fn mapped_in_forked_child(address: *mut libc::c_void, length: usize) -> bool {
        let pid = fork_child(|| {
            // SAFETY: `MADV_NORMAL` only resets read-ahead advice; on a range
            // that is not mapped in this child macOS fails with `EINVAL`.
            if unsafe { libc::madvise(address, length, libc::MADV_NORMAL) } == 0 {
                0
            } else if Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                1
            } else {
                2
            }
        });
        match child_exit_code(pid) {
            0 => true,
            1 => false,
            code => panic!("child probe failed with exit code {code}"),
        }
    }

    #[test]
    fn mappings_share_bytes_and_validate_ranges() {
        let first = MacosSharedMemory::create(64).unwrap();
        let second = MacosSharedMemory::from_received_fd(alias(&first), 64).unwrap();

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
    fn mappings_enforce_control_ring_typed_access() {
        let first = MacosSharedMemory::create_control_ring(LAYOUT).unwrap();
        let second =
            MacosSharedMemory::control_ring_from_received_fd(alias(&first), LAYOUT).unwrap();
        let sequence_offset = first_u64_offset();
        let wake_offset = first_u32_offset();
        let body_offset = (0..MEMORY_SIZE)
            .find(|offset| LAYOUT.permits_byte_range(*offset, 1))
            .unwrap();

        first
            .store_u64_and_increment_u32_release(
                sequence_offset,
                0x0102_0304_0506_0708,
                wake_offset,
            )
            .unwrap();
        assert_eq!(
            second.load_u64_acquire(sequence_offset),
            Ok(0x0102_0304_0506_0708)
        );
        assert_eq!(second.load_u32_acquire(wake_offset), Ok(1));
        second.write(body_offset, &[7]).unwrap();
        let mut byte = [0];
        first.read(body_offset, &mut byte).unwrap();
        assert_eq!(byte, [7]);

        assert_eq!(
            second.read(sequence_offset, &mut byte),
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
        assert_eq!(
            second.store_u64_and_increment_u32_release(sequence_offset, 0, sequence_offset),
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
        assert!(second.raw_bytes().is_none());
    }

    #[test]
    fn shared_wait_returns_without_peer_cooperation() {
        let memory = MacosSharedMemory::create_control_ring(LAYOUT).unwrap();
        let wake_offset = first_u32_offset();

        // The untouched page makes the wait fail at once with `EFAULT`.
        let start = Instant::now();
        memory.wait_while_equal(wake_offset, 0).unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));

        // A recheck faults the page in, after which the wait blocks until its
        // recheck timeout instead of spinning.
        assert_eq!(memory.load_u32_acquire(wake_offset), Ok(0));
        let start = Instant::now();
        memory.wait_while_equal(wake_offset, 0).unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed >= SHARED_WAIT_RECHECK_TIMEOUT / 2 && elapsed < Duration::from_secs(1),
            "bounded wait took {elapsed:?}"
        );

        // A wake with no waiter is not an error.
        memory.wake_one(wake_offset).unwrap();
    }

    #[test]
    fn shared_memory_size_is_fixed_after_creation() {
        for memory in [
            MacosSharedMemory::create(64).unwrap(),
            MacosSharedMemory::create_control_ring(LAYOUT).unwrap(),
        ] {
            let length = memory.len();
            // macOS rounds the object up to whole pages.
            assert!(
                rustix::fs::fstat(&memory.fd).unwrap().st_size >= i64::try_from(length).unwrap()
            );
            let flags = rustix::io::fcntl_getfd(&memory.fd).unwrap();
            assert!(flags.contains(FdFlags::CLOEXEC));
            for new_length in [0, length as u64 - 1, length as u64 + 1, 1 << 20] {
                assert_eq!(
                    ftruncate(&memory.fd, new_length),
                    Err(Errno::INVAL),
                    "resizing a {length}-byte object to {new_length} bytes"
                );
            }
        }
    }

    #[test]
    fn fork_children_do_not_inherit_association_mappings() {
        // SAFETY: A fresh anonymous mapping at a kernel-chosen address replaces nothing.
        let control = unsafe {
            rustix::mm::mmap_anonymous(std::ptr::null_mut(), 1, ProtFlags::READ, MapFlags::PRIVATE)
        }
        .unwrap();
        let control_inherited = mapped_in_forked_child(control, 1);
        // SAFETY: `control` is the 1-byte mapping created above and is not used afterwards.
        unsafe { munmap(control, 1) }.unwrap();
        assert!(
            control_inherited,
            "probe must see ordinary inherited mappings"
        );

        let created = MacosSharedMemory::create(64).unwrap();
        let received = MacosSharedMemory::from_received_fd(alias(&created), 64).unwrap();
        for memory in [&created, &received] {
            assert!(!mapped_in_forked_child(
                memory.mapping.address.as_ptr().cast(),
                memory.mapping.length,
            ));
        }

        created.write(0, &[5]).unwrap();
        let mut byte = [0];
        received.read(0, &mut byte).unwrap();
        assert_eq!(byte, [5]);
    }

    #[test]
    fn rejects_empty_and_oversized_mappings() {
        let memory = MacosSharedMemory::create(64).unwrap();
        assert_eq!(
            MacosSharedMemory::from_received_fd(alias(&memory), 0)
                .err()
                .expect("empty mapping should fail")
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            MacosSharedMemory::create(0)
                .err()
                .expect("empty creation should fail")
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(
            MacosSharedMemory::map(
                alias(&memory),
                isize::MAX as usize + 1,
                MemoryAccessPolicy::Bytes,
            )
            .err()
            .expect("oversized mapping should fail")
            .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn transfers_fixed_size_mappings_with_close_on_exec() {
        let pool = MacosSharedMemory::create(SHARED_BUFFER_POOL_SIZE).unwrap();
        let ring = MacosSharedMemory::create_control_ring(LAYOUT).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_shared_memory(&mut sender, &pool, None).unwrap();
        send_shared_memory(&mut sender, &ring, None).unwrap();
        let received_pool =
            receive_shared_memory(&mut receiver, SHARED_BUFFER_POOL_SIZE, None).unwrap();
        let received_ring = receive_control_ring(&mut receiver, LAYOUT, None).unwrap();

        pool.write(SHARED_BUFFER_POOL_SIZE - 1, &[7]).unwrap();
        let mut byte = [0];
        received_pool
            .read(SHARED_BUFFER_POOL_SIZE - 1, &mut byte)
            .unwrap();
        assert_eq!(byte, [7]);
        assert!(received_pool.raw_bytes().is_some());
        assert_eq!(received_ring.len(), MEMORY_SIZE);
        for received in [&received_pool, &received_ring] {
            let flags = rustix::io::fcntl_getfd(&received.fd).unwrap();
            assert!(flags.contains(FdFlags::CLOEXEC));
            // The receiving peer cannot resize the broker's object either.
            assert_eq!(ftruncate(&received.fd, 0), Err(Errno::INVAL));
        }
    }

    #[test]
    fn shared_wake_reaches_waiter_in_another_process() {
        let memory = MacosSharedMemory::create_control_ring(LAYOUT).unwrap();
        let wake_offset = first_u32_offset();
        let address = checked_u32_address(&memory, wake_offset).unwrap();
        let raw_fd = memory.fd.as_raw_fd();

        let pid = fork_child(|| {
            // `VM_INHERIT_NONE` keeps the parent's mapping out of this child,
            // so it maps the inherited descriptor itself, as a peer would.
            // SAFETY: A shared mapping of the inherited object at a
            // kernel-chosen address replaces nothing.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    MEMORY_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    raw_fd,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                return 2;
            }
            // `wake_offset` is aligned for `u32` within a page-aligned mapping.
            #[allow(clippy::cast_ptr_alignment)]
            let address = mapping.cast::<u8>().wrapping_add(wake_offset).cast::<u32>();
            let retry_delay = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            // Retry until the parent is blocked, which a successful wake reports.
            for _ in 0..10_000 {
                match shared_wake_one(address) {
                    Ok(true) => return 0,
                    Ok(false) => {}
                    Err(_) => return 3,
                }
                // SAFETY: `retry_delay` is a valid timespec and the remainder is unused.
                unsafe { libc::nanosleep(&raw const retry_delay, std::ptr::null_mut()) };
            }
            1
        });

        // Fault the page in, as a ring endpoint's recheck does before waiting.
        assert_eq!(memory.load_u32_acquire(wake_offset), Ok(0));
        // Unlike `wait_while_equal`, this wait reports a timeout, so success
        // means the child's wake arrived.
        loop {
            match shared_wait(address, 0, Duration::from_secs(10)) {
                Ok(()) => break,
                Err(error) if error.raw_os_error() == Some(libc::EINTR) => {}
                Err(error) => panic!("cross-process wake did not arrive: {error}"),
            }
        }
        assert_eq!(child_exit_code(pid), 0);
    }

    #[test]
    fn rejects_missing_multiple_and_truncated_descriptors() {
        let length = 8;

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        sender.write_all(&[0]).unwrap();
        assert_eq!(
            receive_shared_memory(&mut receiver, length, None)
                .err()
                .expect("missing descriptor must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let memory = MacosSharedMemory::create(length).unwrap();
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        send_test_fds(&mut sender, &[memory.fd.as_fd(), memory.fd.as_fd()]);
        assert_eq!(
            receive_shared_memory(&mut receiver, length, None)
                .err()
                .expect("multiple descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );

        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        let fd = memory.fd.as_fd();
        send_test_fds(&mut sender, &[fd, fd, fd, fd, fd]);
        assert_eq!(
            receive_shared_memory(&mut receiver, length, None)
                .err()
                .expect("truncated descriptors must be rejected")
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn reports_peer_close_and_expired_deadline() {
        let length = 8;
        let memory = MacosSharedMemory::create(length).unwrap();
        // Under a deadline, XNU rejects the socket timeout once the peer has
        // closed; the transfer must still report the close itself.
        let deadline = Some(Instant::now() + Duration::from_secs(2));
        let (mut receiver, sender) = UnixStream::pair().unwrap();
        drop(sender);
        assert_eq!(
            receive_shared_memory(&mut receiver, length, deadline)
                .err()
                .expect("setup EOF must be reported")
                .kind(),
            ErrorKind::UnexpectedEof
        );
        let (receiver, mut sender) = UnixStream::pair().unwrap();
        drop(receiver);
        assert_eq!(
            send_shared_memory(&mut sender, &memory, deadline)
                .expect_err("send to a closed peer must fail")
                .kind(),
            ErrorKind::BrokenPipe
        );

        // An expired deadline fails without changing the socket's own timeout.
        let expired = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let timeout = Some(Duration::from_secs(2));
        let (mut receiver, mut sender) = UnixStream::pair().unwrap();
        receiver.set_read_timeout(timeout).unwrap();
        sender.set_write_timeout(timeout).unwrap();
        assert_eq!(
            receive_shared_memory(&mut receiver, length, Some(expired))
                .err()
                .expect("expired setup deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(receiver.read_timeout().unwrap(), timeout);
        assert_eq!(
            send_shared_memory(&mut sender, &memory, Some(expired))
                .expect_err("expired send deadline must be rejected")
                .kind(),
            ErrorKind::TimedOut
        );
        assert_eq!(sender.write_timeout().unwrap(), timeout);
    }

    fn send_test_fds(stream: &mut UnixStream, fds: &[BorrowedFd<'_>]) {
        let carrier = [0];
        let io = [IoSlice::new(&carrier)];
        let mut control_space = crate::control_space::<{ rustix::cmsg_space!(ScmRights(8)) }>();
        let mut control = SendAncillaryBuffer::new(&mut control_space);
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        assert_eq!(
            rustix::net::sendmsg(stream.as_fd(), &io, &mut control, SendFlags::empty()).unwrap(),
            1
        );
    }
}
