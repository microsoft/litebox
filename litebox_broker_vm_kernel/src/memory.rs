// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The association's shared memory, in pinned pages, through the kernel's
//! mapping: the shared buffers, populated as they are accessed, and the
//! control ring. The runner may write either at any time, from other CPUs.

use crate::{CONTROL_RING_LAYOUT, CONTROL_RING_SIZE};
use alloc::sync::Arc;
use core::ops::Range;
use litebox_broker_transport::shared_memory::{ControlRingMemory, SharedMemory, SharedMemoryError};
use litebox_platform::peer_memory;
use litebox_platform_vm_kernel::PinnedUserPages;

/// Calls `copy` for each page's part of `offset..offset + len` of `pages`,
/// with that part's range within `0..len`.
fn for_each_page_part(
    pages: &PinnedUserPages,
    offset: usize,
    len: usize,
    mut copy: impl FnMut(*mut u8, Range<usize>),
) -> Result<(), SharedMemoryError> {
    let mut done = 0;
    while done < len {
        let (address, available) = pages
            .kernel_address(offset + done)
            .map_err(|_| SharedMemoryError::AccessFailed)?;
        let part = available.min(len - done);
        copy(address, done..done + part);
        done += part;
    }
    Ok(())
}

/// The shared buffers, pinned lazily (see
/// `VmKernel::pin_user_pages_lazily`).
pub(crate) struct UserSharedMemory(PinnedUserPages);

impl UserSharedMemory {
    pub(crate) const fn new(pages: PinnedUserPages) -> Self {
        Self(pages)
    }

    /// [`for_each_page_part`] of the shared buffers, once the whole range is
    /// checked: a page not found then (`ENOMEM`) fails the copy with
    /// `AccessFailed`, after the earlier pages' bytes were copied, as
    /// [`SharedMemory`] allows.
    fn for_each_part(
        &self,
        offset: usize,
        len: usize,
        copy: impl FnMut(*mut u8, Range<usize>),
    ) -> Result<(), SharedMemoryError> {
        if offset.checked_add(len).is_none_or(|end| end > self.len()) {
            return Err(SharedMemoryError::InvalidRange);
        }
        for_each_page_part(&self.0, offset, len, copy)
    }
}

// Safety (below): pinned for `self`'s lifetime, in bounds (checked), and
// disjoint from private memory.
impl SharedMemory for UserSharedMemory {
    fn len(&self) -> usize {
        self.0.len()
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

/// The control ring at the start of pinned pages, through the kernel's
/// mapping. Accesses keep to [`CONTROL_RING_LAYOUT`].
#[derive(Clone)]
pub(crate) struct PinnedControlRing(Arc<PinnedUserPages>);

impl PinnedControlRing {
    /// `None` if `pages` cannot hold the ring.
    pub(crate) fn new(pages: PinnedUserPages) -> Option<Self> {
        (pages.len() >= CONTROL_RING_SIZE).then_some(Self(Arc::new(pages)))
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
            .map_err(|_| SharedMemoryError::InvalidRange)?;
        Ok(address.cast())
    }

    fn u32_at(&self, offset: usize) -> Result<*mut u32, SharedMemoryError> {
        self.word(offset, CONTROL_RING_LAYOUT.permits_u32(offset))
    }

    fn u64_at(&self, offset: usize) -> Result<*mut u64, SharedMemoryError> {
        self.word(offset, CONTROL_RING_LAYOUT.permits_u64(offset))
    }

    /// Calls `copy` for each page's part of `offset..offset + len`, with that
    /// part's range within `0..len`.
    fn for_each_part(
        &self,
        offset: usize,
        len: usize,
        copy: impl FnMut(*mut u8, Range<usize>),
    ) -> Result<(), SharedMemoryError> {
        if !CONTROL_RING_LAYOUT.permits_byte_range(offset, len) {
            return Err(SharedMemoryError::InvalidRange);
        }
        for_each_page_part(&self.0, offset, len, copy)
    }
}

// Safety (below): pinned for `self`'s lifetime, in bounds and aligned
// (checked), and disjoint from private memory.
impl SharedMemory for PinnedControlRing {
    fn len(&self) -> usize {
        CONTROL_RING_SIZE
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

    fn store_u32_release(&self, offset: usize, value: u32) -> Result<(), SharedMemoryError> {
        let address = self.u32_at(offset)?;
        // Safety: see above.
        unsafe { peer_memory::store_u32_release(address, value) };
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
