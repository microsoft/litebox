//! Memory management module including:
//! - Memory provider
//! - Page table management

use buddy_system_allocator::Heap;

pub mod buddy;
pub mod slab;
#[cfg(test)]
pub mod tests;

pub trait MemoryProvider {
    /// For page allocation.
    ///
    /// It can return more than requested size. On success, it returns the start address
    /// and the size of the allocated memory.
    fn alloc(layout: &core::alloc::Layout) -> Result<(usize, usize), crate::error::Errno>;

    fn rescue_heap<const ORDER: usize>(heap: &mut Heap<ORDER>, layout: &core::alloc::Layout) {
        match Self::alloc(layout) {
            Ok((start, size)) => {
                // TODO: init reference count for allocated pages
                unsafe { heap.add_to_heap(start, start + size) };
            }
            Err(_) => {
                panic!("OOM");
            }
        }
    }
}

/// Macro to define a global allocator using [`slab::LockedSlabAllocator`].
///
/// [`SafeSlabAllocator`] is a wrapper around [`slab::LockedSlabAllocator`] using
/// [`once_cell::race::OnceBox`] to ensure thread-safe initialization. Since we cannot
/// implement the external trait `GlobalAlloc` for the external struct `OnceBox`, we need
/// to define a new struct [`SafeSlabAllocator`] that implements `GlobalAlloc`.
///
/// ## Arguments
///
/// * name - The name of the global allocator.
/// * order - The order of the buddy allocator (See [`buddy_system_allocator::Heap`]).
/// * platform - The platform type implementing [`litebox::platform::RawMutexProvider`] and [`MemoryProvider`]
/// * sync - expression to pass a synchronization object to [`slab::LockedSlabAllocator::new`].
///
/// ## Example
/// ```
/// lazy_static::lazy_static!(
///     static ref PLATFORM: crate::host::snp::snp_impl::SnpLinuxKernel = crate::host::snp::snp_impl::SnpLinuxKernel::new();
///     static ref SYNC: litebox::sync::Synchronization<'static, crate::host::snp::snp_impl::SnpLinuxKernel>  = litebox::sync::Synchronization::new(&PLATFORM);
/// );
///
/// define_global_allocator!(
///     SLAB_ALLOCATOR,
///     23,
///     crate::host::snp::snp_impl::SnpLinuxKernel,
///     &SYNC
/// );
/// ```
#[macro_export]
macro_rules! define_global_allocator {
    ($name:ident, $order:literal, $platform:ty, $sync:expr) => {
        #[global_allocator]
        static $name: SafeSlabAllocator<'static, $order, $platform> = SafeSlabAllocator::new();

        pub struct SafeSlabAllocator<
            'a,
            const ORDER: usize,
            Platform: litebox::platform::RawMutexProvider + $crate::mem::MemoryProvider,
        >(once_cell::race::OnceBox<$crate::mem::slab::LockedSlabAllocator<'a, ORDER, Platform>>);

        impl<'a, const ORDER: usize> SafeSlabAllocator<'a, ORDER, $platform> {
            pub const fn new() -> Self {
                SafeSlabAllocator(once_cell::race::OnceBox::new())
            }

            pub fn get(&self) -> &$crate::mem::slab::LockedSlabAllocator<'a, ORDER, $platform> {
                self.0
                    .get_or_init(|| alloc::boxed::Box::new($crate::mem::slab::LockedSlabAllocator::new($sync)))
            }
        }

        unsafe impl<'a, const ORDER: usize> core::alloc::GlobalAlloc
            for SafeSlabAllocator<'a, ORDER, $platform>
        {
            unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
                self.get().alloc(layout)
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
                self.get().dealloc(ptr, layout);
            }
        }
    };
}
