// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Real Vulkan ICD loader — dynamic library integration.
//!
//! When the `real_vulkan` feature is enabled this module attempts to
//! load the host system's Vulkan ICD loader (`libvulkan.so.1`) at
//! runtime via `dlopen(3)` and exposes a [`resolve_vulkan_symbol`]
//! helper that the stub functions in `vulkan1.rs` use to forward calls
//! to the real implementation.
//!
//! If the library is not installed the stubs fall back gracefully to
//! their original headless behaviour without panicking.
//!
//! # Package installation
//!
//! On Debian / Ubuntu the required packages are:
//! ```text
//! sudo apt-get install -y libvulkan1 mesa-vulkan-drivers
//! ```
//! `libvulkan1` provides the ICD loader (`libvulkan.so.1`).
//! `mesa-vulkan-drivers` provides a software-only Vulkan driver
//! (lavapipe) that allows functional testing on machines without a GPU.

use std::ffi::CString;
use std::sync::OnceLock;

/// Opaque wrapper around a `dlopen(3)` handle.
///
/// # Safety
/// A handle returned by `dlopen` may safely be sent across threads and
/// shared between them; the lock on the underlying link-map is provided
/// by the dynamic linker itself.
struct VulkanHandle(*mut libc::c_void);

// SAFETY: See the type-level safety comment above.
unsafe impl Send for VulkanHandle {}
// SAFETY: See the type-level safety comment above.
unsafe impl Sync for VulkanHandle {}

/// Lazily loaded handle to the real Vulkan ICD loader library.
static REAL_VULKAN_LIB: OnceLock<Option<VulkanHandle>> = OnceLock::new();

/// Try to open the Vulkan loader library.
///
/// Attempts the versioned name first (`libvulkan.so.1`) and falls back
/// to the unversioned soname (`libvulkan.so`) for environments that only
/// install the development symlink.
fn load_real_vulkan() -> Option<VulkanHandle> {
    for lib_name in &["libvulkan.so.1", "libvulkan.so"] {
        let Ok(c_name) = CString::new(*lib_name) else {
            continue;
        };
        // SAFETY: `c_name` is a valid null-terminated C string.
        //
        // `RTLD_LOCAL` (rather than `RTLD_GLOBAL`) is used deliberately: it
        // keeps the Vulkan symbols scoped to this handle and avoids polluting
        // the process-wide symbol table, which would risk shadowing symbols in
        // other loaded libraries and causing hard-to-debug test failures.
        let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL) };
        if !handle.is_null() {
            return Some(VulkanHandle(handle));
        }
    }
    None
}

/// Resolve a Vulkan function symbol from the real ICD loader library.
///
/// Returns the raw symbol address cast to `*const ()`, or `None` if
/// the library could not be loaded or the symbol is not found.
///
/// The returned pointer is valid as long as the library remains loaded
/// (i.e., for the lifetime of the process).
pub fn resolve_vulkan_symbol(name: &str) -> Option<*const ()> {
    let lib = REAL_VULKAN_LIB.get_or_init(load_real_vulkan).as_ref()?.0;
    let c_name = CString::new(name).ok()?;
    // SAFETY: `lib` is a valid `dlopen` handle; `c_name` is a valid
    // null-terminated C string.
    let sym = unsafe { libc::dlsym(lib, c_name.as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(sym.cast::<()>())
    }
}

/// Return `true` if the real Vulkan ICD loader was found and loaded.
///
/// Triggers the one-time library load as a side effect.
pub fn is_real_vulkan_available() -> bool {
    REAL_VULKAN_LIB.get_or_init(load_real_vulkan).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The loader must not panic even when Vulkan is unavailable.
    #[test]
    fn test_availability_does_not_panic() {
        // We do not assert a specific result because the test may run on
        // hosts that either do or do not have libvulkan installed.
        let _ = is_real_vulkan_available();
    }

    /// Symbol resolution must not panic even when Vulkan is unavailable.
    #[test]
    fn test_resolve_symbol_does_not_panic() {
        // Again, just check it doesn't panic.
        let _ = resolve_vulkan_symbol("vkCreateInstance");
    }
}
