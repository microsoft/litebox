//! An implementation of [`crate::HostInterface`] for MSHV

#[allow(unsafe_code)]
#[allow(dead_code)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(unused_imports)]
#[allow(improper_ctypes)]
#[allow(clippy::all)]
pub mod msr {
    include!(concat!(env!("OUT_DIR"), "/msr_bindings.rs"));
}

mod mshv_impl;

pub use mshv_impl::LvbsLinuxKernel;
