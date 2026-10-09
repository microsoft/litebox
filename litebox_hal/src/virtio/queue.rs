// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Split virtqueues. A request is a chain of buffers (device-readable, then
//! device-writable), identified by its head descriptor until the device
//! returns it. The driver keeps its own record of chains and the free list,
//! so a device that writes nonsense into the used ring cannot corrupt them.

use super::Error;
use crate::dma::{DmaRegion, Hal};
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
const DESC_SIZE: usize = 16;

/// One buffer of a chain, in DMA memory.
#[derive(Clone, Copy, Debug)]
pub struct Buffer {
    pub pa: u64,
    pub len: u32,
    /// The device writes it (else reads it). Device-writable buffers follow
    /// all device-readable ones in a chain.
    pub device_writes: bool,
}

pub struct VirtQueue {
    index: u16,
    size: u16,
    notify_offset: usize,
    /// Descriptors, then the available ring; the used ring at `used`.
    ring: DmaRegion,
    avail: usize,
    used: usize,
    /// Private copies of each descriptor's `next`, threading the free list
    /// and in-flight chains.
    next: Vec<u16>,
    /// By head: the length of an in-flight chain, else zero.
    in_flight: Vec<u16>,
    free_head: u16,
    num_free: u16,
    next_avail: u16,
    last_used: u16,
}

// Safety: the queue exclusively owns its ring.
unsafe impl Send for VirtQueue {}

impl VirtQueue {
    /// `size` must be a power of two; see `PciTransport::setup_queue`.
    pub(super) fn new(
        hal: &'static dyn Hal,
        index: u16,
        size: u16,
        notify_offset: usize,
    ) -> Result<Self, Error> {
        assert!(size.is_power_of_two());
        let n = usize::from(size);
        // Alignments: descriptors 16, available ring 2, used ring 4.
        let avail = DESC_SIZE * n;
        let used = (avail + 6 + 2 * n).next_multiple_of(4);
        let ring = DmaRegion::new(hal, used + 6 + 8 * n).ok_or(Error::OutOfMemory)?;
        Ok(Self {
            index,
            size,
            notify_offset,
            ring,
            avail,
            used,
            next: (1..=size).collect(),
            in_flight: vec![0; n],
            free_head: 0,
            num_free: size,
            next_avail: 0,
            last_used: 0,
        })
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn size(&self) -> u16 {
        self.size
    }

    pub(super) fn notify_offset(&self) -> usize {
        self.notify_offset
    }

    /// The descriptor table's, available ring's, and used ring's addresses.
    pub(super) fn addresses(&self) -> [u64; 3] {
        let pa = self.ring.pa();
        [pa, pa + self.avail as u64, pa + self.used as u64]
    }

    fn write<T>(&self, offset: usize, value: T) {
        // Safety: in bounds (checked by `ptr`) and naturally aligned (the
        // layout keeps every field so); the driver's part of the ring.
        unsafe {
            self.ring
                .ptr(offset, size_of::<T>())
                .cast::<T>()
                .write_volatile(value);
        }
    }

    fn read<T>(&self, offset: usize) -> T {
        // Safety: as for `write`; the device's part is read volatile.
        unsafe {
            self.ring
                .ptr(offset, size_of::<T>())
                .cast::<T>()
                .read_volatile()
        }
    }

    /// Makes `chain` available to the device; returns its head, or `None` if
    /// it is empty or there are not enough free descriptors. The device
    /// learns of it at the next [`super::pci::PciTransport::notify`].
    ///
    /// # Safety
    ///
    /// The buffers must stay valid DMA memory, accessed only as the device
    /// permits, until the device returns the chain ([`Self::pop_used`]).
    pub unsafe fn add(&mut self, chain: &[Buffer]) -> Option<u16> {
        let len = u16::try_from(chain.len()).ok()?;
        if len == 0 || len > self.num_free {
            return None;
        }
        let head = self.free_head;
        let mut id = head;
        for (i, buffer) in chain.iter().enumerate() {
            let desc = usize::from(id) * DESC_SIZE;
            let next = self.next[usize::from(id)];
            let mut flags = if buffer.device_writes {
                DESC_F_WRITE
            } else {
                0
            };
            if i + 1 < chain.len() {
                flags |= DESC_F_NEXT;
            }
            self.write(desc, buffer.pa);
            self.write(desc + 8, buffer.len);
            self.write(desc + 12, flags);
            self.write(desc + 14, next);
            if i + 1 < chain.len() {
                id = next;
            }
        }
        self.free_head = self.next[usize::from(id)];
        self.num_free -= len;
        self.in_flight[usize::from(head)] = len;
        let slot = self.avail + 4 + 2 * usize::from(self.next_avail % self.size);
        self.write(slot, head);
        // The device must see the descriptors and slot before the index.
        fence(Ordering::SeqCst);
        self.next_avail = self.next_avail.wrapping_add(1);
        self.write(self.avail + 2, self.next_avail);
        Some(head)
    }

    /// The next chain the device returned: its head, and how many bytes the
    /// device says it wrote (untrusted; clamp before use). Entries for
    /// chains that are not in flight are skipped.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        loop {
            let used_idx: u16 = self.read(self.used + 2);
            if used_idx == self.last_used {
                return None;
            }
            fence(Ordering::Acquire);
            let elem = self.used + 4 + 8 * usize::from(self.last_used % self.size);
            let (id, len): (u32, u32) = (self.read(elem), self.read(elem + 4));
            self.last_used = self.last_used.wrapping_add(1);
            let Some(head) = u16::try_from(id).ok().filter(|&id| id < self.size) else {
                continue;
            };
            let chain_len = core::mem::take(&mut self.in_flight[usize::from(head)]);
            if chain_len == 0 {
                continue;
            }
            let mut tail = head;
            for _ in 1..chain_len {
                tail = self.next[usize::from(tail)];
            }
            self.next[usize::from(tail)] = self.free_head;
            self.free_head = head;
            self.num_free += chain_len;
            return Some((head, len));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dma::Mmio;

    /// Heap memory, with physical = virtual addresses.
    struct HeapHal;

    fn layout(pages: usize) -> core::alloc::Layout {
        core::alloc::Layout::from_size_align(pages * crate::dma::PAGE_SIZE, 4096).unwrap()
    }

    // Safety: heap memory is contiguous and exclusively owned.
    unsafe impl Hal for HeapHal {
        fn dma_alloc(&self, pages: usize) -> Option<(core::ptr::NonNull<u8>, u64)> {
            // Safety: non-zero size.
            let va = core::ptr::NonNull::new(unsafe { alloc::alloc::alloc(layout(pages)) })?;
            Some((va, va.as_ptr() as u64))
        }

        unsafe fn dma_dealloc(&self, va: core::ptr::NonNull<u8>, pages: usize) {
            // Safety: from `dma_alloc` with the same layout.
            unsafe { alloc::alloc::dealloc(va.as_ptr(), layout(pages)) };
        }

        unsafe fn map_mmio(&self, _pa: u64, _len: usize) -> Option<Mmio> {
            None
        }
    }

    fn queue(size: u16) -> VirtQueue {
        VirtQueue::new(&HeapHal, 0, size, 0).unwrap()
    }

    /// Plays the device: returns `id` with `len` in the used ring.
    fn device_returns(queue: &VirtQueue, slot: u16, id: u32, len: u32) {
        let elem = queue.used + 4 + 8 * usize::from(slot % queue.size);
        queue.write(elem, id);
        queue.write(elem + 4, len);
        queue.write(queue.used + 2, slot.wrapping_add(1));
    }

    fn buffer(device_writes: bool) -> Buffer {
        Buffer {
            pa: 0x1000,
            len: 8,
            device_writes,
        }
    }

    #[test]
    fn chains_are_published_and_freed() {
        let mut q = queue(4);
        // Safety: the device never touches the (fake) buffers.
        let head = unsafe { q.add(&[buffer(false), buffer(true)]) }.unwrap();
        assert_eq!(q.num_free, 2);
        let avail_idx: u16 = q.read(q.avail + 2);
        assert_eq!(avail_idx, 1);
        let flags: u16 = q.read(usize::from(head) * DESC_SIZE + 12);
        assert_eq!(flags, DESC_F_NEXT);
        assert_eq!(q.pop_used(), None);
        device_returns(&q, 0, u32::from(head), 5);
        assert_eq!(q.pop_used(), Some((head, 5)));
        assert_eq!(q.num_free, 4);
    }

    #[test]
    fn bogus_and_replayed_used_entries_are_skipped() {
        let mut q = queue(4);
        // Safety: as above.
        let head = unsafe { q.add(&[buffer(true)]) }.unwrap();
        device_returns(&q, 0, 1000, 1); // out of range
        assert_eq!(q.pop_used(), None);
        device_returns(&q, 1, u32::from(head) + 1, 1); // not in flight
        assert_eq!(q.pop_used(), None);
        device_returns(&q, 2, u32::from(head), 1);
        assert_eq!(q.pop_used(), Some((head, 1)));
        device_returns(&q, 3, u32::from(head), 1); // replayed
        assert_eq!(q.pop_used(), None);
        assert_eq!(q.num_free, 4);
        // The free list is intact: the whole queue can be used again.
        // Safety: as above.
        assert!(unsafe { q.add(&[buffer(true); 4]) }.is_some());
    }
}
