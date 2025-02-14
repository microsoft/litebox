//! Different host implementations of [`super::HostInterface`]
pub mod linux;
#[cfg(test)]
pub mod mock;
#[cfg(feature = "platform_snp")]
mod snp;
