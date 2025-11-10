//! Different host implementations of [`super::HostInterface`]
pub mod hv_impl;
pub mod linux;
pub mod per_cpu_variables;

pub use hv_impl::Hypervisor;

#[cfg(test)]
pub mod mock;
