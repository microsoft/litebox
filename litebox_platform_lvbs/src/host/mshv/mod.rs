//! An implementation of [`crate::HostInterface`] for MSHV

#[expect(non_camel_case_types)]
#[expect(non_upper_case_globals)]
pub mod msr_index {
    include!(concat!(env!("OUT_DIR"), "/msr_index_bindings.rs"));
}

mod mshv_impl;

pub use mshv_impl::LvbsLinuxKernel;
