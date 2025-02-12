//! Different host implementations of [`super::HostInterface`]
#[cfg(feature = "platform_snp")]
pub(crate) mod ghcb;
pub mod linux;
#[cfg(feature = "platform_snp")]
pub mod snp;
