//! Different host implementations of [`super::HostInterface`]
pub mod linux;
pub mod mshv;

#[cfg(test)]
pub mod mock;
