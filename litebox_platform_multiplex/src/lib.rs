//! A multiplexer for [LiteBox platforms](../litebox/platform/index.html), to simplify access to a
//! global platform for shims "above" LiteBox.
//!
//! At a high level, due to Rust language design decisions, supporting a **global**
//! runtime-parametric platform is not quite directly feasible. In particular, either
//! platform-dependent functionality either needs to be aware of the platform, or each function
//! would need a parametric platform, neither of which is ideal. This crate side-steps that by using
//! conditional compilation (at this single crate) to provide the necessary switching between
//! platforms.
//!
//! Specifically, a platform MUST be selected via one of the features provided by this crate (and
//! cannot be provided dynamically at run-time). However, crates above it can then work with a
//! global platform _without_ needing to deal with any such switching. If a LiteBox platform exists
//! that does not have a corresponding feature in this crate, support for it is easy to add.
//!
//! By default, this crate picks the Linux userland platform.

#![no_std]

extern crate alloc;

// Checking if more than one of the platforms has been specified. If so, compiler error.
//
// NOTE: Currently, we only support one platform, thus this is a trivial no-op. However, once we
// have more, we must account for each of the possible pairs.
cfg_if::cfg_if! {
    if #[cfg(all(feature = "platform_linux_userland", target_os = "linux"))] {
        pub type Platform = litebox_platform_linux_userland::LinuxUserland;
    } else if #[cfg(all(feature = "platform_windows_userland", target_os = "windows"))] {
        pub type Platform = litebox_platform_windows_userland::WindowsUserland;
    } else if #[cfg(feature = "platform_lvbs")] {
        pub type Platform = litebox_platform_lvbs::host::LvbsLinuxKernel;
    } else if #[cfg(feature = "platform_linux_snp")] {
        pub type Platform = litebox_platform_linux_kernel::host::snp::snp_impl::SnpLinuxKernel;
    } else if #[cfg(feature = "platform_kernel")] {
        pub type Platform = litebox_platform_kernel::LiteBoxKernel;
    } else {
        compile_error!(
            r##"Hint: you might have forgotten to mark 'default-features = false'."##
        );
    }
}

static PLATFORM: once_cell::race::OnceBox<&'static Platform> = once_cell::race::OnceBox::new();

/// Initialize the shim by providing a [LiteBox platform](../litebox/platform/index.html).
///
/// **Must** be invoked prior to any of the other functionality provided by this crate; all other
/// functionality is prone to panics if this has not been invoked first.
///
/// # Panics
///
/// Panics if invoked more than once
#[expect(
    clippy::match_wild_err_arm,
    reason = "the platform itself is not Debug thus we cannot use `expect`"
)]
pub fn set_platform(platform: &'static Platform) {
    match PLATFORM.set(alloc::boxed::Box::new(platform)) {
        Ok(()) => {}
        Err(_) => panic!("set_platform should only be called once per crate"),
    }
}

/// Get the global platform, or panic if [`set_platform`] has not yet been invoked.
///
/// # Panics
///
/// Panics if [`set_platform`] has not been invoked before this
pub fn platform() -> &'static Platform {
    PLATFORM
        .get()
        .expect("set_platform should have already been called before this point")
}
