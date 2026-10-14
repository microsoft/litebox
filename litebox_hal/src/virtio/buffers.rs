// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Fixed-size buffers in one DMA region, each a one-descriptor chain while
//! the device has it: what the console and network devices exchange data
//! in.

use super::Error;
use super::queue::{Buffer, VirtQueue};
use crate::dma::{DmaRegion, Hal};
use alloc::vec;
use alloc::vec::Vec;

pub(super) struct Buffers {
    memory: DmaRegion,
    size: usize,
    /// By queue head: the buffer the device has.
    by_head: Vec<Option<u16>>,
    /// Buffers the device does not have.
    pub(super) free: Vec<u16>,
}

impl Buffers {
    /// `count` buffers of `size` bytes, or fewer if `queue` has fewer
    /// entries.
    pub(super) fn new(
        hal: &'static dyn Hal,
        queue: &VirtQueue,
        count: u16,
        size: usize,
    ) -> Result<Self, Error> {
        let count = count.min(queue.size());
        Ok(Self {
            memory: DmaRegion::new(hal, usize::from(count) * size).ok_or(Error::OutOfMemory)?,
            size,
            by_head: vec![None; usize::from(queue.size())],
            free: (0..count).rev().collect(),
        })
    }

    pub(super) fn size(&self) -> usize {
        self.size
    }

    pub(super) fn ptr(&self, buffer: u16, offset: usize, len: usize) -> *mut u8 {
        assert!(offset + len <= self.size);
        self.memory
            .ptr(usize::from(buffer) * self.size + offset, len)
    }

    /// Lends `len` bytes of a free buffer to the device.
    pub(super) fn post(
        &mut self,
        queue: &mut VirtQueue,
        buffer: u16,
        len: usize,
        device_writes: bool,
    ) {
        let chain = [Buffer {
            pa: self.memory.pa() + (usize::from(buffer) * self.size) as u64,
            len: u32::try_from(len.min(self.size)).expect("buffers are small"),
            device_writes,
        }];
        // Safety: the buffer is ours (free) and DMA memory that lives as
        // long as the device's driver; it is not accessed until the device
        // returns it.
        let head = unsafe { queue.add(&chain) }.expect("a descriptor per buffer");
        self.by_head[usize::from(head)] = Some(buffer);
    }

    /// The next buffer the device returned, and the length it wrote, which
    /// is not trusted beyond the buffer's size.
    pub(super) fn take_used(&mut self, queue: &mut VirtQueue) -> Option<(u16, usize)> {
        let (head, len) = queue.pop_used()?;
        let buffer = self.by_head[usize::from(head)]
            .take()
            .expect("in-flight chains are posted buffers");
        Some((
            buffer,
            usize::try_from(len).map_or(self.size, |len| len.min(self.size)),
        ))
    }
}
