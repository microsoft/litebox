//! An implementation of [`crate::HostInterface`] for SNP VMM

mod ghcb;
mod snp_impl;

pub use snp_impl::SnpLinuxKenrel;
