//! Different host implementations of [`super::HostInterface`]
pub mod linux;
#[cfg(feature = "platform_snp")]
mod snp;
