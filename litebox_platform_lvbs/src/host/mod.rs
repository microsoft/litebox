//! Different host implementations of [`super::HostInterface`]
pub mod bootparam;
pub mod linux;
pub mod lvbs_impl;
pub mod per_cpu_variables;

pub use lvbs_impl::LvbsLinuxKernel;

#[cfg(test)]
pub mod mock;
