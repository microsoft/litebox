//! Arch-specific code

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::*;

#[cfg(target_arch = "x86_64")]
#[expect(
    clippy::cast_possible_truncation,
    reason = "on 64-bit, u64 -> usize will fit"
)]
pub const PAGE_SIZE: usize = Size4KiB::SIZE as usize;
