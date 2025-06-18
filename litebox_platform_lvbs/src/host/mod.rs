//! Different host implementations of [`super::HostInterface`]
pub mod bootparam;
pub(crate) mod kernel_elf;
pub mod linux;
pub mod lvbs_impl;

pub use lvbs_impl::LvbsLinuxKernel;

#[cfg(test)]
pub mod mock;
