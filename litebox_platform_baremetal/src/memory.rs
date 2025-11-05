//! Memory management for the baremetal platform
//! Handles page allocation, deallocation, and protection

use buddy_system_allocator::LockedHeap;
use core::sync::atomic::{AtomicU32, Ordering};
use litebox::platform::page_mgmt::{
    AllocationError, DeallocationError, MemoryRegionPermissions, PermissionUpdateError,
};
use litebox::platform::{ImmediatelyWokenUp, RawMutex, UnblockedOrTimedOut};
use spin::Mutex;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};

#[global_allocator]
static ALLOCATOR: LockedHeap<32> = LockedHeap::empty();

/// Initialize the heap allocator
///
/// # Safety
/// This must be called only once during boot with valid heap bounds
pub unsafe fn init_heap(heap_start: usize, heap_size: usize) {
    unsafe { ALLOCATOR.lock().init(heap_start, heap_size) };
}

/// Simple frame allocator using a fixed memory range
pub struct BootFrameAllocator {
    next_frame: PhysFrame,
    end_frame: PhysFrame,
}

impl BootFrameAllocator {
    pub unsafe fn new(start: usize, size: usize) -> Self {
        let start_addr = x86_64::PhysAddr::new(start as u64);
        let end_addr = x86_64::PhysAddr::new((start + size) as u64);
        Self {
            next_frame: PhysFrame::containing_address(start_addr),
            end_frame: PhysFrame::containing_address(end_addr),
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if self.next_frame < self.end_frame {
            let frame = self.next_frame;
            self.next_frame += 1;
            Some(frame)
        } else {
            None
        }
    }
}

static PAGE_ALLOCATOR: Mutex<Option<BootFrameAllocator>> = Mutex::new(None);

/// Initialize the page allocator
///
/// # Safety
/// This must be called only once during boot with valid physical memory bounds
pub unsafe fn init_page_allocator(start: usize, size: usize) {
    *PAGE_ALLOCATOR.lock() = Some(unsafe { BootFrameAllocator::new(start, size) });
}

/// Allocate pages in the specified range
pub fn allocate_pages_in_range(
    suggested_range: core::ops::Range<usize>,
    _initial_permissions: MemoryRegionPermissions,
) -> Result<crate::ptr::UserMutPtr<u8>, AllocationError> {
    let mut allocator = PAGE_ALLOCATOR.lock();
    let allocator = allocator.as_mut().ok_or(AllocationError::OutOfMemory)?;

    let num_pages = (suggested_range.end - suggested_range.start) / 4096;
    if num_pages == 0 {
        return Err(AllocationError::InvalidRange);
    }

    let start_frame = allocator
        .allocate_frame()
        .ok_or(AllocationError::OutOfMemory)?;

    // Allocate remaining frames
    for _ in 1..num_pages {
        allocator
            .allocate_frame()
            .ok_or(AllocationError::OutOfMemory)?;
    }

    let start_addr = start_frame.start_address().as_u64() as usize;
    Ok(crate::ptr::UserMutPtr::new(start_addr))
}

/// Deallocate pages (currently a no-op, frames are not reclaimed)
pub fn deallocate_pages(_range: core::ops::Range<usize>) -> Result<(), DeallocationError> {
    // In a simple allocator, we don't reclaim pages
    // A more sophisticated allocator would return frames to a free list
    Ok(())
}

/// Update page permissions
pub fn update_permissions(
    _range: core::ops::Range<usize>,
    _new_permissions: MemoryRegionPermissions,
) -> Result<(), PermissionUpdateError> {
    // For now, just return success
    // A full implementation would need to update page table entries
    Ok(())
}

/// Raw mutex implementation using a spinlock
pub struct SpinlockRawMutex {
    value: AtomicU32,
}

impl SpinlockRawMutex {
    pub const fn new() -> Self {
        Self {
            value: AtomicU32::new(0),
        }
    }
}

impl RawMutex for SpinlockRawMutex {
    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.value
    }

    fn wake_many(&self, _n: usize) -> usize {
        // No actual threads to wake, this is a no-op
        0
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        if self.value.load(Ordering::Acquire) != val {
            Err(ImmediatelyWokenUp)
        } else {
            // Spin until value changes
            while self.value.load(Ordering::Acquire) == val {
                core::hint::spin_loop();
            }
            Ok(())
        }
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        if self.value.load(Ordering::Acquire) != val {
            return Err(ImmediatelyWokenUp);
        }

        let start = unsafe { core::arch::x86_64::_rdtsc() };
        let cpu_mhz = crate::get_cpu_mhz();
        let timeout_cycles = if cpu_mhz == 0 {
            u64::MAX
        } else {
            timeout.as_nanos() as u64 * cpu_mhz / 1000
        };

        loop {
            if self.value.load(Ordering::Acquire) != val {
                return Ok(UnblockedOrTimedOut::Unblocked);
            }

            let now = unsafe { core::arch::x86_64::_rdtsc() };
            if now.saturating_sub(start) >= timeout_cycles {
                return Ok(UnblockedOrTimedOut::TimedOut);
            }

            core::hint::spin_loop();
        }
    }
}
