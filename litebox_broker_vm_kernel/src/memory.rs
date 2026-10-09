// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The association's shared memory: the shared buffers in the process's lazy
//! mapping, and the control ring in pinned pages.

use alloc::sync::Arc;
use core::ops::Range;
use litebox::mm::exception_table::{Fault, memcpy_fallible};
use litebox::platform::common_providers::userspace_pointers::ValidateAccess as _;
use litebox_broker_transport::control_ring::{CONTROL_RING_MEMORY_SIZE, MemoryAccessPolicy};
use litebox_broker_transport::peer_memory;
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_common_vm_abi::UserRange;
use litebox_platform_vm_kernel::{PinnedUserPages, VmValidateAccess};

/// The shared buffers, through the process's mapping: valid only while its
/// address space is current.
pub(crate) struct UserSharedMemory {
    region: UserRange,
}

impl UserSharedMemory {
    pub(crate) const fn new(region: UserRange) -> Self {
        Self { region }
    }

    /// The user address of `offset..offset + len`, validated.
    fn user(&self, offset: usize, len: usize) -> Result<*mut u8, SharedMemoryError> {
        let end = offset
            .checked_add(len)
            .ok_or(SharedMemoryError::InvalidRange)?;
        if end > self.len() {
            return Err(SharedMemoryError::InvalidRange);
        }
        let start =
            usize::try_from(self.region.start).map_err(|_| SharedMemoryError::InvalidRange)?;
        VmValidateAccess::validate_slice(core::ptr::slice_from_raw_parts_mut(
            (start + offset) as *mut u8,
            len,
        ))
        .ok_or(SharedMemoryError::InvalidRange)
    }
}

/// Runs a fallible copy with user memory access open.
fn copy_fallible(copy: impl FnOnce() -> Result<(), Fault>) -> Result<(), SharedMemoryError> {
    VmValidateAccess::with_user_memory_access(copy).map_err(|_| SharedMemoryError::AccessFailed)
}

impl SharedMemory for UserSharedMemory {
    fn len(&self) -> usize {
        usize::try_from(self.region.len).unwrap_or(0)
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        let source = self.user(offset, destination.len())?;
        // Safety: `destination` is private; `source` is validated user memory,
        // whose faults are recovered.
        copy_fallible(|| unsafe {
            memcpy_fallible(destination.as_mut_ptr(), source, destination.len())
        })
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        let destination = self.user(offset, source.len())?;
        // Safety: as in `read`.
        copy_fallible(|| unsafe { memcpy_fallible(destination, source.as_ptr(), source.len()) })
    }
}

/// The control ring at the start of pinned pages, through the kernel's
/// mapping. Accesses keep to [`MemoryAccessPolicy::ControlRing`].
#[derive(Clone)]
pub(crate) struct PinnedControlRing(Arc<PinnedUserPages>);

impl PinnedControlRing {
    /// `None` if `pages` cannot hold the ring.
    pub(crate) fn new(pages: PinnedUserPages) -> Option<Self> {
        (pages.len() >= CONTROL_RING_MEMORY_SIZE).then_some(Self(Arc::new(pages)))
    }

    fn word<T>(&self, offset: usize, permitted: bool) -> Result<*mut T, SharedMemoryError> {
        if !permitted {
            return Err(SharedMemoryError::InvalidRange);
        }
        if !offset.is_multiple_of(size_of::<T>()) {
            return Err(SharedMemoryError::UnalignedWord);
        }
        // An aligned word never crosses a page.
        let (address, _) = self
            .0
            .kernel_address(offset)
            .ok_or(SharedMemoryError::InvalidRange)?;
        Ok(address.cast())
    }

    fn u32_at(&self, offset: usize) -> Result<*mut u32, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u32(offset))
    }

    fn u64_at(&self, offset: usize) -> Result<*mut u64, SharedMemoryError> {
        self.word(offset, MemoryAccessPolicy::ControlRing.permits_u64(offset))
    }

    /// Calls `copy` for each page's part of `offset..offset + len`, with that
    /// part's range within `0..len`.
    fn for_each_part(
        &self,
        offset: usize,
        len: usize,
        mut copy: impl FnMut(*mut u8, Range<usize>),
    ) -> Result<(), SharedMemoryError> {
        if !MemoryAccessPolicy::ControlRing.permits_byte_range(offset, len) {
            return Err(SharedMemoryError::InvalidRange);
        }
        let mut done = 0;
        while done < len {
            let (address, available) = self
                .0
                .kernel_address(offset + done)
                .ok_or(SharedMemoryError::InvalidRange)?;
            let part = available.min(len - done);
            copy(address, done..done + part);
            done += part;
        }
        Ok(())
    }
}

// Safety (below): pinned for `self`'s lifetime, in bounds and aligned
// (checked), and disjoint from private memory.
impl SharedMemory for PinnedControlRing {
    fn len(&self) -> usize {
        CONTROL_RING_MEMORY_SIZE
    }

    fn read(&self, offset: usize, destination: &mut [u8]) -> Result<(), SharedMemoryError> {
        self.for_each_part(offset, destination.len(), |source, part| {
            // Safety: see above.
            unsafe { peer_memory::copy_from_peer(source, &mut destination[part]) };
        })
    }

    fn write(&self, offset: usize, source: &[u8]) -> Result<(), SharedMemoryError> {
        self.for_each_part(offset, source.len(), |destination, part| {
            // Safety: see above.
            unsafe { peer_memory::copy_to_peer(&source[part], destination) };
        })
    }
}

impl ControlRingMemory for PinnedControlRing {
    fn load_u32_acquire(&self, offset: usize) -> Result<u32, SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        Ok(unsafe { peer_memory::load_u32_acquire(address) })
    }

    fn increment_u32_release(&self, offset: usize) -> Result<(), SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::increment_u32_release(address) };
        Ok(())
    }

    fn load_u64_acquire(&self, offset: usize) -> Result<u64, SharedMemoryError> {
        let address = self.u64_at(offset)?;
        // Safety: see above.
        Ok(unsafe { peer_memory::load_u64_acquire(address) })
    }

    fn store_u64_release(&self, offset: usize, value: u64) -> Result<(), SharedMemoryError> {
        let address = self.u64_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::store_u64_release(address, value) };
        Ok(())
    }

    fn store_u64_and_increment_u32_release(
        &self,
        store_offset: usize,
        value: u64,
        increment_offset: usize,
    ) -> Result<(), SharedMemoryError> {
        let store = self.u64_at(store_offset)?;
        let increment = self.u32_at(increment_offset)?;
        // Safety: see above.
        unsafe {
            peer_memory::store_u64_release(store, value);
            peer_memory::increment_u32_release(increment);
        }
        Ok(())
    }
}
