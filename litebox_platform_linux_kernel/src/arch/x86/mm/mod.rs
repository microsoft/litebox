//! Memory management module for x86 architecture.

pub(crate) mod paging;

core::arch::global_asm!(include_str!("memcpy_fallible.S"));

unsafe extern "C" {
    /// Copies `size` bytes from `src` to `dst`. This function works with exception handling
    /// and can recover from page fault.
    /// Returns number of bytes that failed to copy.
    pub(crate) fn __memcpy_fallible(dst: *mut u8, src: *const u8, size: usize) -> usize;
}
