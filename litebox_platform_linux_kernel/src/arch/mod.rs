//! Arch-specific code

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::*;

pub const PAGE_SIZE: usize = Size4KiB::SIZE as usize;
