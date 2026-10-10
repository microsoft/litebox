// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! What device drivers need from the kernel: memory a device can access
//! (DMA) and device registers (MMIO). The kernel platform implements
//! [`Hal`].

use core::ptr::NonNull;

pub const PAGE_SIZE: usize = 4096;

/// Zeroed, physically contiguous pages from a [`Hal`], which the kernel
/// accesses at `va` and devices at `pa`; returned to the [`Hal`] on drop, so
/// drop a region only once no device can access it (nothing in it is posted).
pub struct DmaRegion {
    va: NonNull<u8>,
    pa: u64,
    len: usize,
    hal: &'static dyn Hal,
}

// Safety: a region is plain memory owned by whoever holds it.
unsafe impl Send for DmaRegion {}
// Safety: as above; shared access goes through raw pointers only.
unsafe impl Sync for DmaRegion {}

impl DmaRegion {
    /// At least `len` bytes; `None` when out of memory.
    pub fn new(hal: &'static dyn Hal, len: usize) -> Option<Self> {
        let pages = len.div_ceil(PAGE_SIZE).max(1);
        let (va, pa) = hal.dma_alloc(pages)?;
        let len = pages * PAGE_SIZE;
        // Safety: freshly allocated and exclusively owned (`Hal` contract).
        unsafe { va.write_bytes(0, len) };
        Some(Self { va, pa, len, hal })
    }

    pub fn pa(&self) -> u64 {
        self.pa
    }

    /// The kernel's pointer to byte `offset`.
    ///
    /// # Panics
    ///
    /// If `offset + size` exceeds the region.
    pub fn ptr(&self, offset: usize, size: usize) -> *mut u8 {
        assert!(
            offset.checked_add(size).is_some_and(|end| end <= self.len),
            "DMA access out of bounds"
        );
        // Safety: within the region.
        unsafe { self.va.as_ptr().add(offset) }
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        // Safety: from `dma_alloc` with this many pages; see the type's docs
        // for device access.
        unsafe { self.hal.dma_dealloc(self.va, self.len / PAGE_SIZE) };
    }
}

/// Device registers, mapped uncacheable. Accesses are volatile and
/// bounds-checked; offsets come from the driver, lengths from the device,
/// checked when the region is created.
#[derive(Clone, Copy, Debug)]
pub struct Mmio {
    base: NonNull<u8>,
    len: usize,
}

// Safety: device registers have no Rust-visible state; drivers serialize
// their protocols themselves.
unsafe impl Send for Mmio {}
// Safety: as above.
unsafe impl Sync for Mmio {}

macro_rules! mmio_accessors {
    ($($read:ident $write:ident $ty:ty;)*) => {$(
        pub fn $read(&self, offset: usize) -> $ty {
            // Safety: in bounds and aligned (checked); a device register.
            unsafe { self.at::<$ty>(offset).read_volatile() }
        }

        pub fn $write(&self, offset: usize, value: $ty) {
            // Safety: as above.
            unsafe { self.at::<$ty>(offset).write_volatile(value) }
        }
    )*};
}

impl Mmio {
    /// # Safety
    ///
    /// `base..base + len` must be device registers mapped uncacheable for the
    /// result's lifetime and not used as memory by anything else.
    pub unsafe fn new(base: NonNull<u8>, len: usize) -> Self {
        Self { base, len }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Device-supplied offsets are validated before they reach here, so an
    /// out-of-bounds or misaligned access is a driver bug.
    fn at<T>(&self, offset: usize) -> *mut T {
        assert!(
            offset
                .checked_add(size_of::<T>())
                .is_some_and(|end| end <= self.len),
            "MMIO access at {offset:#x} outside {:#x} bytes",
            self.len
        );
        // Safety: within the mapping.
        let ptr: *mut T = unsafe { self.base.add(offset).cast().as_ptr() };
        // The address, not just the offset: a structure may start anywhere.
        assert!(ptr.is_aligned(), "misaligned MMIO access at {ptr:p}");
        ptr
    }

    mmio_accessors! {
        read_u8 write_u8 u8;
        read_u16 write_u16 u16;
        read_u32 write_u32 u32;
    }
}

/// # Safety
///
/// `dma_alloc` must return `pages` physically contiguous pages at `pa`,
/// mapped writable at the returned address and exclusively owned until
/// `dma_dealloc`. `map_mmio` must uphold [`Mmio::new`]'s contract.
pub unsafe trait Hal: Sync {
    /// `None` when out of memory.
    fn dma_alloc(&self, pages: usize) -> Option<(NonNull<u8>, u64)>;

    /// # Safety
    ///
    /// From `dma_alloc` with the same `pages`; no device accesses it.
    unsafe fn dma_dealloc(&self, va: NonNull<u8>, pages: usize);

    /// Maps the device registers at physical `pa..pa + len` for the kernel's
    /// lifetime; `None` if they cannot be (e.g., they overlap RAM).
    ///
    /// # Safety
    ///
    /// `pa..pa + len` must be device registers, e.g., within a BAR.
    unsafe fn map_mmio(&self, pa: u64, len: usize) -> Option<Mmio>;
}

#[cfg(test)]
mod tests {
    use super::Mmio;
    use core::ptr::NonNull;

    #[test]
    #[should_panic(expected = "misaligned")]
    fn misaligned_address_is_refused() {
        let mut memory = [0u64; 4];
        // Safety: plain memory, alive for the test.
        let mmio = unsafe { Mmio::new(NonNull::from(&mut memory).cast::<u8>().add(2), 30) };
        mmio.read_u32(0);
    }
}
