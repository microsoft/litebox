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
/// The farthest a used index can be ahead: half the index space (serial
/// numbers, as in RFC 1982). Farther, it moved back.
const MAX_ADVANCE: u16 = 0x8000;

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
    refused: Refused,
}

/// Used-ring entries [`VirtQueue::pop_used`] refused, by kind; the first of
/// each kind is warned of.
#[derive(Default)]
struct Refused {
    /// Calls that found the used index moved back.
    moved_back: u64,
    /// Entries overwritten unread.
    overwritten: u64,
    /// Entries naming no chain in flight.
    not_in_flight: u64,
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
            refused: Refused::default(),
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

    /// How far the used index is past the entries looked at.
    fn returned(&self) -> u16 {
        let used_idx: u16 = self.read(self.used + 2);
        used_idx.wrapping_sub(self.last_used)
    }

    /// Whether [`Self::pop_used`] has used-ring entries to look at.
    pub(super) fn has_used(&self) -> bool {
        (1..=MAX_ADVANCE).contains(&self.returned())
    }

    #[cfg(test)]
    fn refused(&self) -> u64 {
        let Refused {
            moved_back,
            overwritten,
            not_in_flight,
        } = self.refused;
        moved_back + overwritten + not_in_flight
    }

    /// The next chain the device returned: its head, and how many bytes the
    /// device says it wrote (untrusted; clamp before use).
    ///
    /// Looks at most at `size` entries per call, each at most once. Skips
    /// entries naming no chain in flight (they free nothing), entries
    /// overwritten by an index more than `size` ahead (their chains stay in
    /// flight), and everything while the index is behind.
    pub fn pop_used(&mut self) -> Option<(u16, u32)> {
        let returned = self.returned();
        if returned == 0 {
            return None;
        }
        if returned > MAX_ADVANCE {
            if self.refused.moved_back == 0 {
                litebox_util_log::warn!(
                    queue:% = self.index;
                    "virtio device moved its used index back; refused"
                );
            }
            self.refused.moved_back += 1;
            return None;
        }
        if returned > self.size {
            let overwritten = returned - self.size;
            if self.refused.overwritten == 0 {
                litebox_util_log::warn!(
                    queue:% = self.index,
                    overwritten:% = overwritten;
                    "virtio device overran its used ring; skipped what it overwrote"
                );
            }
            self.refused.overwritten += u64::from(overwritten);
            self.last_used = self.last_used.wrapping_add(overwritten);
        }
        fence(Ordering::Acquire);
        for _ in 0..returned.min(self.size) {
            let elem = self.used + 4 + 8 * usize::from(self.last_used % self.size);
            let (id, len): (u32, u32) = (self.read(elem), self.read(elem + 4));
            self.last_used = self.last_used.wrapping_add(1);
            let in_flight = u16::try_from(id)
                .ok()
                .filter(|&id| id < self.size && self.in_flight[usize::from(id)] != 0);
            let Some(head) = in_flight else {
                if self.refused.not_in_flight == 0 {
                    litebox_util_log::warn!(
                        queue:% = self.index,
                        id:% = id;
                        "virtio device returned a buffer it does not have; skipped"
                    );
                }
                self.refused.not_in_flight += 1;
                continue;
            };
            let chain_len = core::mem::take(&mut self.in_flight[usize::from(head)]);
            let mut tail = head;
            for _ in 1..chain_len {
                tail = self.next[usize::from(tail)];
            }
            self.next[usize::from(tail)] = self.free_head;
            self.free_head = head;
            self.num_free += chain_len;
            return Some((head, len));
        }
        None
    }
}

/// A device in memory, for driver tests.
#[cfg(test)]
pub(super) mod fake {
    use super::{DESC_SIZE, VirtQueue};
    use crate::dma::{Hal, Mmio};

    /// Heap memory, with physical = virtual addresses.
    pub(in crate::virtio) struct HeapHal;

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

    pub(in crate::virtio) fn queue(index: u16, size: u16) -> VirtQueue {
        VirtQueue::new(&HeapHal, index, size, 0).unwrap()
    }

    /// The device's side of a queue of one-descriptor chains.
    #[derive(Default)]
    pub(in crate::virtio) struct Device {
        /// The next available-ring entry to use.
        next_avail: u16,
        used_idx: u16,
    }

    impl Device {
        /// Returns `id` with `len` in the used ring.
        pub(in crate::virtio) fn returns(&mut self, queue: &VirtQueue, id: u32, len: u32) {
            let elem = queue.used + 4 + 8 * usize::from(self.used_idx % queue.size);
            queue.write(elem, id);
            queue.write(elem + 4, len);
            self.used_idx = self.used_idx.wrapping_add(1);
            queue.write(queue.used + 2, self.used_idx);
        }

        /// The next available buffer: its head, address, and length.
        fn next(&mut self, queue: &VirtQueue) -> Option<(u16, *mut u8, usize)> {
            let avail_idx: u16 = queue.read(queue.avail + 2);
            if avail_idx == self.next_avail {
                return None;
            }
            let slot = queue.avail + 4 + 2 * usize::from(self.next_avail % queue.size);
            let head: u16 = queue.read(slot);
            self.next_avail = self.next_avail.wrapping_add(1);
            let desc = usize::from(head) * DESC_SIZE;
            let (pa, len): (u64, u32) = (queue.read(desc), queue.read(desc + 8));
            let buffer = core::ptr::with_exposed_provenance_mut::<u8>(pa.try_into().unwrap());
            Some((head, buffer, len.try_into().unwrap()))
        }

        /// Fills the next available buffer with `bytes` (truncated, but
        /// reported whole) and returns it; false if none is available.
        pub(in crate::virtio) fn fill(&mut self, queue: &VirtQueue, bytes: &[u8]) -> bool {
            let Some((head, buffer, len)) = self.next(queue) else {
                return false;
            };
            // Safety: `HeapHal` memory the driver lent the device.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len().min(len)) };
            self.returns(queue, u32::from(head), u32::try_from(bytes.len()).unwrap());
            true
        }

        /// The bytes of the next available buffer, which it returns.
        pub(in crate::virtio) fn take(&mut self, queue: &VirtQueue) -> Option<alloc::vec::Vec<u8>> {
            let (head, buffer, len) = self.next(queue)?;
            // Safety: `HeapHal` memory the driver lent the device, `len`
            // bytes long.
            let bytes = unsafe { core::slice::from_raw_parts(buffer, len) }.to_vec();
            self.returns(queue, u32::from(head), 0);
            Some(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(size: u16) -> VirtQueue {
        fake::queue(0, size)
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
        fake::Device::default().returns(&q, u32::from(head), 5);
        assert_eq!(q.pop_used(), Some((head, 5)));
        assert_eq!(q.pop_used(), None);
        assert_eq!(q.num_free, 4);
    }

    #[test]
    fn bogus_and_replayed_used_entries_are_skipped() {
        let mut q = queue(4);
        // Safety: as above.
        let heads: [u16; 4] = core::array::from_fn(|_| unsafe { q.add(&[buffer(true)]) }.unwrap());
        let mut device = fake::Device::default();
        device.returns(&q, 1000, 1); // out of range
        device.returns(&q, u32::from(heads[0]), 1);
        assert_eq!(q.pop_used(), Some((heads[0], 1)));
        device.returns(&q, u32::from(heads[0]), 1); // replayed: no longer in flight
        assert_eq!(q.pop_used(), None);
        assert!(!q.has_used());
        assert_eq!(q.refused(), 2);
        device.returns(&q, u32::from(heads[1]), 1);
        assert_eq!(q.pop_used(), Some((heads[1], 1)));
        assert_eq!(q.num_free, 2);
        // The skipped entries cost no later chain its return.
        device.returns(&q, u32::from(heads[2]), 2);
        device.returns(&q, u32::from(heads[3]), 3);
        assert_eq!(q.pop_used(), Some((heads[2], 2)));
        assert_eq!(q.pop_used(), Some((heads[3], 3)));
        assert_eq!(q.pop_used(), None);
        assert_eq!(q.num_free, 4);
        // The free list is intact: the whole queue can be used again.
        // Safety: as above.
        assert!(unsafe { q.add(&[buffer(true); 4]) }.is_some());
        assert_eq!(q.refused(), 2);
    }

    /// An overrun used ring: a chain whose return was overwritten stays in
    /// flight.
    #[test]
    fn an_overrun_used_ring_is_resynchronized() {
        let mut q = queue(4);
        // Safety: as above.
        let heads: [u16; 2] = core::array::from_fn(|_| unsafe { q.add(&[buffer(true)]) }.unwrap());
        let mut device = fake::Device::default();
        device.returns(&q, u32::from(heads[0]), 1);
        for _ in 0..10 {
            device.returns(&q, 1000, 1);
        }
        assert_eq!(q.pop_used(), None);
        assert!(!q.has_used());
        assert_eq!(q.refused(), 11);
        // Its return was lost: the device may still own it.
        assert_eq!(q.num_free, 2);
        device.returns(&q, u32::from(heads[1]), 2);
        assert_eq!(q.pop_used(), Some((heads[1], 2)));
        assert_eq!(q.pop_used(), None);
        assert_eq!(q.num_free, 3);
    }

    /// A slot written once is read once, even if its chain is lent again.
    #[test]
    fn an_overwritten_slot_is_not_replayed_after_reposting() {
        let mut q = queue(4);
        // Safety: as above.
        let head = unsafe { q.add(&[buffer(true)]) }.unwrap();
        let mut device = fake::Device::default();
        for _ in 0..4 {
            device.returns(&q, 1000, 1);
        }
        // Over the first slot.
        device.returns(&q, u32::from(head), 5);
        assert_eq!(q.pop_used(), Some((head, 5)));
        // Safety: as above.
        assert_eq!(unsafe { q.add(&[buffer(true)]) }, Some(head));
        assert_eq!(q.pop_used(), None);
        assert!(!q.has_used());
        assert_eq!((q.refused(), q.num_free), (4, 3));
    }

    /// A used index moved back replays nothing, even for a chain lent again.
    #[test]
    fn a_used_index_moved_back_replays_nothing() {
        let mut q = queue(4);
        // Safety: as above.
        let heads: [u16; 4] = core::array::from_fn(|_| unsafe { q.add(&[buffer(true)]) }.unwrap());
        let mut device = fake::Device::default();
        device.returns(&q, u32::from(heads[0]), 5);
        assert_eq!(q.pop_used(), Some((heads[0], 5)));
        // Safety: as above.
        assert_eq!(unsafe { q.add(&[buffer(true)]) }, Some(heads[0]));
        // Back to 0, without writing anything.
        let mut device = fake::Device::default();
        q.write(q.used + 2, 0u16);
        assert!(!q.has_used());
        assert_eq!(q.pop_used(), None);
        assert_eq!(q.pop_used(), None);
        assert_eq!((q.refused(), q.num_free), (2, 0));
        // Entries rewritten below the old index are lost; later ones are read.
        device.returns(&q, u32::from(heads[0]), 6);
        assert_eq!(q.pop_used(), None);
        device.returns(&q, u32::from(heads[1]), 7);
        assert_eq!(q.pop_used(), Some((heads[1], 7)));
        assert_eq!(q.pop_used(), None);
        assert_eq!((q.refused(), q.num_free), (2, 1));
    }
}
