//! Hyper-V-specific code

pub mod hvcall;
pub mod vtl1_mem_layout;

/// MSHV-specific bindings generated from the MSHV and VSM headers. We do not use
/// the official mshv crate because it does not support `no_std`.
#[expect(clippy::cast_lossless)]
#[expect(clippy::cast_possible_truncation)]
#[expect(clippy::cast_possible_wrap)]
#[expect(clippy::default_trait_access)]
#[expect(clippy::missing_safety_doc)]
#[expect(clippy::unnecessary_cast)]
#[expect(clippy::used_underscore_binding)]
#[expect(clippy::useless_transmute)]
#[expect(clippy::ptr_as_ptr)]
#[expect(clippy::ptr_offset_with_cast)]
#[expect(clippy::pub_underscore_fields)]
#[expect(clippy::ref_as_ptr)]
#[expect(clippy::semicolon_if_nothing_returned)]
#[expect(clippy::similar_names)]
#[expect(clippy::too_many_arguments)]
#[expect(clippy::too_many_lines)]
#[expect(clippy::transmute_ptr_to_ptr)]
#[expect(non_camel_case_types)]
#[expect(non_snake_case)]
#[expect(non_upper_case_globals)]
#[expect(unsafe_code)]
#[expect(unsafe_op_in_unsafe_fn)]
pub mod mshv_bindings {
    include!(concat!(env!("OUT_DIR"), "/mshv_bindings.rs"));
}
