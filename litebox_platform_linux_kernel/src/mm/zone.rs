//! This is copied from slabmalloc::zone.rs with some modifications.
//! See [`ZoneAllocator`] for details.

use core::{alloc::Layout, ptr::NonNull};

use slabmalloc::{AllocationError, LargeObjectPage, ObjectPage, SCAllocator};
use spin::mutex::SpinMutex;

/// A zone allocator for arbitrary sized allocations.
///
/// Similar to [`slabmalloc::ZoneAllocator`], but each slab has a separate [`spin::mutex::SpinMutex`].
/// Note we use [`spin::mutex::SpinMutex`] instead of our own Mutex because SpinMutex does not require
/// an allocator, which breaks the circular dependency.
pub struct ZoneAllocator<'a> {
    small_slabs: [SpinMutex<SCAllocator<'a, ObjectPage<'a>>>; ZoneAllocator::MAX_BASE_SIZE_CLASSES],
    big_slabs:
        [SpinMutex<SCAllocator<'a, LargeObjectPage<'a>>>; ZoneAllocator::MAX_LARGE_SIZE_CLASSES],
}

enum Slab {
    Base(usize),
    Large(usize),
    Unsupported,
}

impl<'a> ZoneAllocator<'a> {
    /// Maximum size that allocated within LargeObjectPages (2 MiB).
    /// This is also the maximum object size that this allocator can handle.
    pub const MAX_ALLOC_SIZE: usize = 1 << 17;

    /// Maximum size which is allocated with ObjectPages (4 KiB pages).
    ///
    /// e.g. this is 4 KiB - 80 bytes of meta-data.
    pub const MAX_BASE_ALLOC_SIZE: usize = 256;

    /// How many allocators of type [`SCAllocator<ObjectPage>`] we have.
    const MAX_BASE_SIZE_CLASSES: usize = 6;

    /// How many allocators of type [`SCAllocator<LargeObjectPage>`] we have.
    const MAX_LARGE_SIZE_CLASSES: usize = 9;

    pub(super) const fn new() -> Self {
        ZoneAllocator {
            small_slabs: [
                SpinMutex::new(SCAllocator::new(8)),
                SpinMutex::new(SCAllocator::new(16)),
                SpinMutex::new(SCAllocator::new(32)),
                SpinMutex::new(SCAllocator::new(64)),
                SpinMutex::new(SCAllocator::new(128)),
                SpinMutex::new(SCAllocator::new(256)),
            ],
            big_slabs: [
                SpinMutex::new(SCAllocator::new(512)),
                SpinMutex::new(SCAllocator::new(1024)),
                SpinMutex::new(SCAllocator::new(2048)),
                SpinMutex::new(SCAllocator::new(4096)),
                SpinMutex::new(SCAllocator::new(8192)),
                SpinMutex::new(SCAllocator::new(16384)),
                SpinMutex::new(SCAllocator::new(32768)),
                SpinMutex::new(SCAllocator::new(65536)),
                SpinMutex::new(SCAllocator::new(131072)),
            ],
        }
    }

    /// Figure out index into zone array to get the correct slab allocator for that size.
    fn get_slab(requested_size: usize) -> Slab {
        match requested_size {
            0..=8 => Slab::Base(0),
            9..=16 => Slab::Base(1),
            17..=32 => Slab::Base(2),
            33..=64 => Slab::Base(3),
            65..=128 => Slab::Base(4),
            129..=256 => Slab::Base(5),
            257..=512 => Slab::Large(0),
            513..=1024 => Slab::Large(1),
            1025..=2048 => Slab::Large(2),
            2049..=4096 => Slab::Large(3),
            4097..=8192 => Slab::Large(4),
            8193..=16384 => Slab::Large(5),
            16385..=32767 => Slab::Large(6),
            32768..=65536 => Slab::Large(7),
            65537..=131_072 => Slab::Large(8),
            _ => Slab::Unsupported,
        }
    }

    /// Allocate a pointer to a block of memory described by `layout`.
    pub(super) fn allocate(&self, layout: Layout) -> Result<NonNull<u8>, AllocationError> {
        match ZoneAllocator::get_slab(layout.size()) {
            Slab::Base(idx) => self.small_slabs[idx].lock().allocate(layout),
            Slab::Large(idx) => self.big_slabs[idx].lock().allocate(layout),
            Slab::Unsupported => Err(AllocationError::InvalidLayout),
        }
    }

    /// Deallocates a pointer to a block of memory, which was
    /// previously allocated by `allocate`.
    ///
    /// # Arguments
    ///  * `ptr` - Address of the memory location to free.
    ///  * `layout` - Memory layout of the block pointed to by `ptr`.
    pub(super) fn deallocate(
        &self,
        ptr: NonNull<u8>,
        layout: Layout,
    ) -> Result<(), AllocationError> {
        match ZoneAllocator::get_slab(layout.size()) {
            Slab::Base(idx) => self.small_slabs[idx].lock().deallocate(ptr, layout),
            Slab::Large(idx) => self.big_slabs[idx].lock().deallocate(ptr, layout),
            Slab::Unsupported => Err(AllocationError::InvalidLayout),
        }
    }

    /// Refills the SCAllocator for a given Layout with an ObjectPage
    /// abd allocate a new object.
    ///
    /// # Safety
    /// ObjectPage needs to be emtpy etc.
    pub(super) unsafe fn refill_and_allocate(
        &self,
        layout: Layout,
        new_page: &'a mut ObjectPage<'a>,
    ) -> Result<NonNull<u8>, AllocationError> {
        match ZoneAllocator::get_slab(layout.size()) {
            Slab::Base(idx) => {
                let mut locked = self.small_slabs[idx].lock();
                locked.refill(new_page);
                locked.allocate(layout)
            }
            Slab::Large(_idx) => Err(AllocationError::InvalidLayout),
            Slab::Unsupported => Err(AllocationError::InvalidLayout),
        }
    }

    /// Refills the SCAllocator for a given Layout with an ObjectPage.
    ///
    /// # Safety
    /// ObjectPage needs to be emtpy etc.
    pub(super) unsafe fn refill_large_and_allocate(
        &self,
        layout: Layout,
        new_page: &'a mut LargeObjectPage<'a>,
    ) -> Result<NonNull<u8>, AllocationError> {
        match ZoneAllocator::get_slab(layout.size()) {
            Slab::Base(_idx) => Err(AllocationError::InvalidLayout),
            Slab::Large(idx) => {
                let mut locked = self.big_slabs[idx].lock();
                locked.refill(new_page);
                locked.allocate(layout)
            }
            Slab::Unsupported => Err(AllocationError::InvalidLayout),
        }
    }
}
