// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! vulkan-1.dll function implementations
//!
//! This module provides stub implementations of the Vulkan API for Windows
//! programs that use Vulkan for rendering.  These stubs allow programs that
//! link against vulkan-1.dll to load and initialize without crashing in a
//! headless Linux environment.  All Vulkan operations return VK_SUCCESS (0)
//! or appropriate error codes so that well-written callers can detect the
//! absence of a real GPU and fall back gracefully.
//!
//! Vulkan return-value constants follow the `VkResult` enumeration:
//! - `VK_SUCCESS` (0) — command successfully completed
//! - `VK_NOT_READY` (1) — a fence or query has not yet completed
//! - `VK_ERROR_INITIALIZATION_FAILED` (-3) — initialization of an object
//!   could not be completed for implementation-specific reasons
//! - `VK_ERROR_INCOMPATIBLE_DRIVER` (-9) — requested Vulkan version not
//!   supported by driver
//!
//! Most instance/device-creation functions return `VK_ERROR_INITIALIZATION_FAILED`
//! to clearly signal that no Vulkan implementation is present.  A small set of
//! query functions (e.g. `vkEnumerateInstanceExtensionProperties`,
//! `vkEnumerateInstanceLayerProperties`) return VK_SUCCESS with a zero count so
//! that programs that query capabilities before creating an instance can
//! determine that no extensions are available rather than crashing.

// Allow unsafe operations inside unsafe functions
#![allow(unsafe_op_in_unsafe_fn)]
// Parameters prefixed with `_` are used when the `real_vulkan` feature is
// enabled (forwarded to the real library), but unused in headless stubs.
#![cfg_attr(feature = "real_vulkan", allow(clippy::used_underscore_binding))]

use core::ffi::c_void;

// ── Real Vulkan pass-through helpers ─────────────────────────────────────────

/// Look up a Vulkan function in the real ICD loader and cast it to `F`.
///
/// Used internally by the `forward_real!` macro.  When the `real_vulkan`
/// feature is enabled this function is called for every Vulkan stub to
/// attempt to forward the call to the host's `libvulkan.so.1`.
///
/// Returns `Some(f)` where `f` is a typed function pointer to the real
/// implementation, or `None` when the library could not be loaded or the
/// symbol is absent (in which case the stub falls through to its headless
/// fallback body).
///
/// # Safety
/// `F` **must** be the correct function-pointer type for the named
/// Vulkan function (matching calling convention, parameter types and
/// return type).  Passing an incorrect `F` is undefined behaviour.
#[cfg(feature = "real_vulkan")]
unsafe fn real_vk<F: Copy>(name: &str) -> Option<F> {
    crate::vulkan_loader::resolve_vulkan_symbol(name).map(|sym| {
        // SAFETY: Caller guarantees that `F` exactly matches the Vulkan ABI
        // of the named function.  Both `*const ()` and any Vulkan function
        // pointer are pointer-sized, satisfying `transmute_copy`'s size
        // requirement.
        unsafe { core::mem::transmute_copy(&sym) }
    })
}

/// No-op expansion used when the `real_vulkan` feature is **disabled**.
///
/// When the feature is inactive the stub functions retain their original
/// headless behaviour and every `forward_real!` invocation compiles away
/// to nothing, leaving only the stub body.
///
/// Usage: `forward_real!("vkName", FnType, arg0, arg1, …);`
#[cfg(not(feature = "real_vulkan"))]
macro_rules! forward_real {
    ($name:literal, $ty:ty, $($arg:expr),*) => {};
}

/// Dispatch variant used when the `real_vulkan` feature is **enabled**.
///
/// Attempts to resolve the named Vulkan symbol from the host's real
/// `libvulkan.so.1` ICD loader via [`real_vk`].  If the symbol is found
/// the call is forwarded to the real implementation and the function
/// returns immediately.  When the symbol cannot be resolved (library
/// absent or symbol missing) execution falls through to the stub body
/// below, which provides the original headless fallback behaviour.
///
/// Usage: `forward_real!("vkName", FnType, arg0, arg1, …);`
#[cfg(feature = "real_vulkan")]
macro_rules! forward_real {
    ($name:literal, $ty:ty, $($arg:expr),*) => {
        // SAFETY: $ty is the correct Vulkan ABI for $name; see real_vk.
        if let Some(f) = unsafe { real_vk::<$ty>($name) } {
            return unsafe { f($($arg),*) };
        }
    };
}

// ── VkResult constants ────────────────────────────────────────────────────────

/// `VK_SUCCESS` — command successfully completed
const VK_SUCCESS: i32 = 0;

/// `VK_NOT_READY` — fence or query has not yet completed
#[allow(dead_code)]
const VK_NOT_READY: i32 = 1;

/// `VK_ERROR_INITIALIZATION_FAILED` — initialization could not be completed
const VK_ERROR_INITIALIZATION_FAILED: i32 = -3;

/// `VK_ERROR_LAYER_NOT_PRESENT` — requested layer is not present
#[allow(dead_code)]
const VK_ERROR_LAYER_NOT_PRESENT: i32 = -6;

/// `VK_ERROR_EXTENSION_NOT_PRESENT` — requested extension is not present
#[allow(dead_code)]
const VK_ERROR_EXTENSION_NOT_PRESENT: i32 = -7;

/// `VK_ERROR_INCOMPATIBLE_DRIVER` — Vulkan version not supported by driver
#[allow(dead_code)]
const VK_ERROR_INCOMPATIBLE_DRIVER: i32 = -9;

// ── Instance & device management ─────────────────────────────────────────────

/// `vkCreateInstance` — create a new Vulkan instance.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no Vulkan ICD is available in the
/// headless environment.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateInstance(
    _create_info: *const c_void,
    _allocator: *const c_void,
    instance: *mut *mut c_void,
) -> i32 {
    forward_real!(
        "vkCreateInstance",
        unsafe extern "C" fn(*const c_void, *const c_void, *mut *mut c_void) -> i32,
        _create_info,
        _allocator,
        instance
    );
    if !instance.is_null() {
        // SAFETY: caller guarantees `instance` is a valid pointer-to-pointer.
        instance.write(core::ptr::null_mut());
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyInstance` — destroy a Vulkan instance.
///
/// No-op; there is no real instance to destroy.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyInstance(
    _instance: *mut c_void,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyInstance",
        unsafe extern "C" fn(*mut c_void, *const c_void),
        _instance,
        _allocator
    );
}

/// `vkEnumerateInstanceExtensionProperties` — query supported global extensions.
///
/// Sets `*property_count` to 0 and returns `VK_SUCCESS`; no extensions are
/// available in the headless stub.
///
/// # Safety
/// `p_property_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkEnumerateInstanceExtensionProperties(
    _layer_name: *const u8,
    p_property_count: *mut u32,
    _p_properties: *mut c_void,
) -> i32 {
    forward_real!(
        "vkEnumerateInstanceExtensionProperties",
        unsafe extern "C" fn(*const u8, *mut u32, *mut c_void) -> i32,
        _layer_name,
        p_property_count,
        _p_properties
    );
    if !p_property_count.is_null() {
        // SAFETY: caller guarantees `p_property_count` is a valid writable pointer.
        p_property_count.write(0);
    }
    VK_SUCCESS
}

/// `vkEnumerateInstanceLayerProperties` — query available layers.
///
/// Sets `*property_count` to 0 and returns `VK_SUCCESS`; no layers are
/// available in the headless stub.
///
/// # Safety
/// `p_property_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkEnumerateInstanceLayerProperties(
    p_property_count: *mut u32,
    _p_properties: *mut c_void,
) -> i32 {
    forward_real!(
        "vkEnumerateInstanceLayerProperties",
        unsafe extern "C" fn(*mut u32, *mut c_void) -> i32,
        p_property_count,
        _p_properties
    );
    if !p_property_count.is_null() {
        // SAFETY: caller guarantees `p_property_count` is a valid writable pointer.
        p_property_count.write(0);
    }
    VK_SUCCESS
}

/// `vkEnumeratePhysicalDevices` — enumerate physical devices accessible to a Vulkan instance.
///
/// Sets `*physical_device_count` to 0 and returns `VK_SUCCESS`; no physical
/// devices are present in the headless stub.
///
/// # Safety
/// `p_physical_device_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkEnumeratePhysicalDevices(
    _instance: *mut c_void,
    p_physical_device_count: *mut u32,
    _p_physical_devices: *mut *mut c_void,
) -> i32 {
    forward_real!(
        "vkEnumeratePhysicalDevices",
        unsafe extern "C" fn(*mut c_void, *mut u32, *mut *mut c_void) -> i32,
        _instance,
        p_physical_device_count,
        _p_physical_devices
    );
    if !p_physical_device_count.is_null() {
        // SAFETY: caller guarantees `p_physical_device_count` is a valid writable pointer.
        p_physical_device_count.write(0);
    }
    VK_SUCCESS
}

/// `vkGetPhysicalDeviceProperties` — return properties of a physical device.
///
/// No-op; there is no real physical device to query.
///
/// # Safety
/// `p_properties` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceProperties(
    _physical_device: *mut c_void,
    _p_properties: *mut c_void,
) {
    forward_real!(
        "vkGetPhysicalDeviceProperties",
        unsafe extern "C" fn(*mut c_void, *mut c_void),
        _physical_device,
        _p_properties
    );
}

/// `vkGetPhysicalDeviceFeatures` — report features supported by a physical device.
///
/// No-op; there is no real physical device.
///
/// # Safety
/// `p_features` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceFeatures(
    _physical_device: *mut c_void,
    _p_features: *mut c_void,
) {
    forward_real!(
        "vkGetPhysicalDeviceFeatures",
        unsafe extern "C" fn(*mut c_void, *mut c_void),
        _physical_device,
        _p_features
    );
}

/// `vkGetPhysicalDeviceQueueFamilyProperties` — report queue family properties.
///
/// Sets `*p_queue_family_property_count` to 0; no queue families available.
///
/// # Safety
/// `p_queue_family_property_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceQueueFamilyProperties(
    _physical_device: *mut c_void,
    p_queue_family_property_count: *mut u32,
    _p_queue_family_properties: *mut c_void,
) {
    forward_real!(
        "vkGetPhysicalDeviceQueueFamilyProperties",
        unsafe extern "C" fn(*mut c_void, *mut u32, *mut c_void),
        _physical_device,
        p_queue_family_property_count,
        _p_queue_family_properties
    );
    if !p_queue_family_property_count.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_queue_family_property_count.write(0);
    }
}

/// `vkGetPhysicalDeviceMemoryProperties` — query memory properties.
///
/// No-op; there is no real physical device.
///
/// # Safety
/// `p_memory_properties` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceMemoryProperties(
    _physical_device: *mut c_void,
    _p_memory_properties: *mut c_void,
) {
    forward_real!(
        "vkGetPhysicalDeviceMemoryProperties",
        unsafe extern "C" fn(*mut c_void, *mut c_void),
        _physical_device,
        _p_memory_properties
    );
}

/// `vkCreateDevice` — create a new device.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no device can be created
/// in the headless environment.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateDevice(
    _physical_device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    device: *mut *mut c_void,
) -> i32 {
    forward_real!(
        "vkCreateDevice",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut *mut c_void) -> i32,
        _physical_device,
        _create_info,
        _allocator,
        device
    );
    if !device.is_null() {
        // SAFETY: caller guarantees `device` is a valid pointer-to-pointer.
        device.write(core::ptr::null_mut());
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyDevice` — destroy a logical device.
///
/// No-op; there is no real device to destroy.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyDevice(_device: *mut c_void, _allocator: *const c_void) {
    forward_real!(
        "vkDestroyDevice",
        unsafe extern "C" fn(*mut c_void, *const c_void),
        _device,
        _allocator
    );
}

/// `vkGetDeviceQueue` — get a queue handle from a device.
///
/// Sets `*p_queue` to null; no real queues are available.
///
/// # Safety
/// `p_queue` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetDeviceQueue(
    _device: *mut c_void,
    _queue_family_index: u32,
    _queue_index: u32,
    p_queue: *mut *mut c_void,
) {
    forward_real!(
        "vkGetDeviceQueue",
        unsafe extern "C" fn(*mut c_void, u32, u32, *mut *mut c_void),
        _device,
        _queue_family_index,
        _queue_index,
        p_queue
    );
    if !p_queue.is_null() {
        // SAFETY: caller guarantees `p_queue` is a valid writable pointer.
        p_queue.write(core::ptr::null_mut());
    }
}

// ── Surface ───────────────────────────────────────────────────────────────────

/// `vkCreateWin32SurfaceKHR` — create a `VkSurfaceKHR` object for a Win32 window.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no real surface can be created in
/// the headless environment.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateWin32SurfaceKHR(
    _instance: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_surface: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateWin32SurfaceKHR",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _instance,
        _create_info,
        _allocator,
        p_surface
    );
    if !p_surface.is_null() {
        // SAFETY: caller guarantees `p_surface` is a valid writable u64 pointer.
        p_surface.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroySurfaceKHR` — destroy a `VkSurfaceKHR` object.
///
/// No-op; there is no real surface to destroy.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroySurfaceKHR(
    _instance: *mut c_void,
    _surface: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroySurfaceKHR",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _instance,
        _surface,
        _allocator
    );
}

/// `vkGetPhysicalDeviceSurfaceSupportKHR` — query if a queue family supports presentation.
///
/// Returns `VK_SUCCESS` and sets `*p_supported` to 0 (not supported) in headless mode.
///
/// # Safety
/// `p_supported` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceSurfaceSupportKHR(
    _physical_device: *mut c_void,
    _queue_family_index: u32,
    _surface: u64,
    p_supported: *mut u32,
) -> i32 {
    forward_real!(
        "vkGetPhysicalDeviceSurfaceSupportKHR",
        unsafe extern "C" fn(*mut c_void, u32, u64, *mut u32) -> i32,
        _physical_device,
        _queue_family_index,
        _surface,
        p_supported
    );
    if !p_supported.is_null() {
        // SAFETY: caller guarantees `p_supported` is a valid writable u32 pointer.
        p_supported.write(0);
    }
    VK_SUCCESS
}

/// `vkGetPhysicalDeviceSurfaceCapabilitiesKHR` — query surface capabilities.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no surface is available in
/// the headless environment.
///
/// # Safety
/// `p_surface_capabilities` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(
    _physical_device: *mut c_void,
    _surface: u64,
    _p_surface_capabilities: *mut c_void,
) -> i32 {
    forward_real!(
        "vkGetPhysicalDeviceSurfaceCapabilitiesKHR",
        unsafe extern "C" fn(*mut c_void, u64, *mut c_void) -> i32,
        _physical_device,
        _surface,
        _p_surface_capabilities
    );
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkGetPhysicalDeviceSurfaceFormatsKHR` — query color formats supported with a surface.
///
/// Returns `VK_SUCCESS` and sets `*p_surface_format_count` to 0.
///
/// # Safety
/// `p_surface_format_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceSurfaceFormatsKHR(
    _physical_device: *mut c_void,
    _surface: u64,
    p_surface_format_count: *mut u32,
    _p_surface_formats: *mut c_void,
) -> i32 {
    forward_real!(
        "vkGetPhysicalDeviceSurfaceFormatsKHR",
        unsafe extern "C" fn(*mut c_void, u64, *mut u32, *mut c_void) -> i32,
        _physical_device,
        _surface,
        p_surface_format_count,
        _p_surface_formats
    );
    if !p_surface_format_count.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_surface_format_count.write(0);
    }
    VK_SUCCESS
}

/// `vkGetPhysicalDeviceSurfacePresentModesKHR` — query present modes for a surface.
///
/// Returns `VK_SUCCESS` and sets `*p_present_mode_count` to 0.
///
/// # Safety
/// `p_present_mode_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetPhysicalDeviceSurfacePresentModesKHR(
    _physical_device: *mut c_void,
    _surface: u64,
    p_present_mode_count: *mut u32,
    _p_present_modes: *mut c_void,
) -> i32 {
    forward_real!(
        "vkGetPhysicalDeviceSurfacePresentModesKHR",
        unsafe extern "C" fn(*mut c_void, u64, *mut u32, *mut c_void) -> i32,
        _physical_device,
        _surface,
        p_present_mode_count,
        _p_present_modes
    );
    if !p_present_mode_count.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_present_mode_count.write(0);
    }
    VK_SUCCESS
}

// ── Swapchain ─────────────────────────────────────────────────────────────────

/// `vkCreateSwapchainKHR` — create a swapchain.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no swapchain can be created in
/// the headless environment.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateSwapchainKHR(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_swapchain: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateSwapchainKHR",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_swapchain
    );
    if !p_swapchain.is_null() {
        // SAFETY: caller guarantees `p_swapchain` is a valid writable u64 pointer.
        p_swapchain.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroySwapchainKHR` — destroy a swapchain.
///
/// No-op; there is no real swapchain to destroy.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroySwapchainKHR(
    _device: *mut c_void,
    _swapchain: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroySwapchainKHR",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _swapchain,
        _allocator
    );
}

/// `vkGetSwapchainImagesKHR` — obtain the array of presentable images associated with a swapchain.
///
/// Returns `VK_SUCCESS` and sets `*p_swapchain_image_count` to 0.
///
/// # Safety
/// `p_swapchain_image_count` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetSwapchainImagesKHR(
    _device: *mut c_void,
    _swapchain: u64,
    p_swapchain_image_count: *mut u32,
    _p_swapchain_images: *mut u64,
) -> i32 {
    forward_real!(
        "vkGetSwapchainImagesKHR",
        unsafe extern "C" fn(*mut c_void, u64, *mut u32, *mut u64) -> i32,
        _device,
        _swapchain,
        p_swapchain_image_count,
        _p_swapchain_images
    );
    if !p_swapchain_image_count.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_swapchain_image_count.write(0);
    }
    VK_SUCCESS
}

/// `vkAcquireNextImageKHR` — retrieve the index of the next available presentable image.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no images are available in the headless stub.
///
/// # Safety
/// `p_image_index` must be a valid writable pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkAcquireNextImageKHR(
    _device: *mut c_void,
    _swapchain: u64,
    _timeout: u64,
    _semaphore: u64,
    _fence: u64,
    p_image_index: *mut u32,
) -> i32 {
    forward_real!(
        "vkAcquireNextImageKHR",
        unsafe extern "C" fn(*mut c_void, u64, u64, u64, u64, *mut u32) -> i32,
        _device,
        _swapchain,
        _timeout,
        _semaphore,
        _fence,
        p_image_index
    );
    if !p_image_index.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_image_index.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkQueuePresentKHR` — queue an image for presentation.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no presentation is possible in headless mode.
///
/// # Safety
/// `p_present_info` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkQueuePresentKHR(
    _queue: *mut c_void,
    _p_present_info: *const c_void,
) -> i32 {
    forward_real!(
        "vkQueuePresentKHR",
        unsafe extern "C" fn(*mut c_void, *const c_void) -> i32,
        _queue,
        _p_present_info
    );
    VK_ERROR_INITIALIZATION_FAILED
}

// ── Memory & Resources ────────────────────────────────────────────────────────

/// `vkAllocateMemory` — allocate device memory.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no device memory is available.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkAllocateMemory(
    _device: *mut c_void,
    _allocate_info: *const c_void,
    _allocator: *const c_void,
    p_memory: *mut u64,
) -> i32 {
    forward_real!(
        "vkAllocateMemory",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _allocate_info,
        _allocator,
        p_memory
    );
    if !p_memory.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_memory.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkFreeMemory` — free device memory.
///
/// No-op; there is no real device memory to free.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkFreeMemory(
    _device: *mut c_void,
    _memory: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkFreeMemory",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _memory,
        _allocator
    );
}

/// `vkCreateBuffer` — create a new buffer object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateBuffer(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_buffer: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateBuffer",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_buffer
    );
    if !p_buffer.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_buffer.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyBuffer` — destroy a buffer object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyBuffer(
    _device: *mut c_void,
    _buffer: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyBuffer",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _buffer,
        _allocator
    );
}

/// `vkCreateImage` — create a new image object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateImage(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_image: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateImage",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_image
    );
    if !p_image.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_image.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyImage` — destroy an image object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyImage(
    _device: *mut c_void,
    _image: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyImage",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _image,
        _allocator
    );
}

// ── Render passes & pipelines ─────────────────────────────────────────────────

/// `vkCreateRenderPass` — create a new render pass object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateRenderPass(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_render_pass: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateRenderPass",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_render_pass
    );
    if !p_render_pass.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_render_pass.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyRenderPass` — destroy a render pass object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyRenderPass(
    _device: *mut c_void,
    _render_pass: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyRenderPass",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _render_pass,
        _allocator
    );
}

/// `vkCreateFramebuffer` — create a new framebuffer object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateFramebuffer(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_framebuffer: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateFramebuffer",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_framebuffer
    );
    if !p_framebuffer.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_framebuffer.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyFramebuffer` — destroy a framebuffer object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyFramebuffer(
    _device: *mut c_void,
    _framebuffer: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyFramebuffer",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _framebuffer,
        _allocator
    );
}

/// `vkCreateGraphicsPipelines` — create graphics pipeline objects.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateGraphicsPipelines(
    _device: *mut c_void,
    _pipeline_cache: u64,
    _create_info_count: u32,
    _p_create_infos: *const c_void,
    _allocator: *const c_void,
    p_pipelines: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateGraphicsPipelines",
        unsafe extern "C" fn(*mut c_void, u64, u32, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _pipeline_cache,
        _create_info_count,
        _p_create_infos,
        _allocator,
        p_pipelines
    );
    if !p_pipelines.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_pipelines.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyPipeline` — destroy a pipeline object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyPipeline(
    _device: *mut c_void,
    _pipeline: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyPipeline",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _pipeline,
        _allocator
    );
}

/// `vkCreateShaderModule` — create a shader module.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateShaderModule(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_shader_module: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateShaderModule",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_shader_module
    );
    if !p_shader_module.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_shader_module.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyShaderModule` — destroy a shader module.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyShaderModule(
    _device: *mut c_void,
    _shader_module: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyShaderModule",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _shader_module,
        _allocator
    );
}

// ── Command pools & buffers ───────────────────────────────────────────────────

/// `vkCreateCommandPool` — create a new command pool.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateCommandPool(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_command_pool: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateCommandPool",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_command_pool
    );
    if !p_command_pool.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_command_pool.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyCommandPool` — destroy a command pool.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyCommandPool(
    _device: *mut c_void,
    _command_pool: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyCommandPool",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _command_pool,
        _allocator
    );
}

/// `vkAllocateCommandBuffers` — allocate command buffers from an existing pool.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkAllocateCommandBuffers(
    _device: *mut c_void,
    _allocate_info: *const c_void,
    _p_command_buffers: *mut *mut c_void,
) -> i32 {
    forward_real!(
        "vkAllocateCommandBuffers",
        unsafe extern "C" fn(*mut c_void, *const c_void, *mut *mut c_void) -> i32,
        _device,
        _allocate_info,
        _p_command_buffers
    );
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkFreeCommandBuffers` — free command buffers.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkFreeCommandBuffers(
    _device: *mut c_void,
    _command_pool: u64,
    _command_buffer_count: u32,
    _p_command_buffers: *const *mut c_void,
) {
    forward_real!(
        "vkFreeCommandBuffers",
        unsafe extern "C" fn(*mut c_void, u64, u32, *const *mut c_void),
        _device,
        _command_pool,
        _command_buffer_count,
        _p_command_buffers
    );
}

/// `vkBeginCommandBuffer` — start recording a command buffer.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no real command buffer exists.
///
/// # Safety
/// `p_begin_info` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkBeginCommandBuffer(
    _command_buffer: *mut c_void,
    _p_begin_info: *const c_void,
) -> i32 {
    forward_real!(
        "vkBeginCommandBuffer",
        unsafe extern "C" fn(*mut c_void, *const c_void) -> i32,
        _command_buffer,
        _p_begin_info
    );
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkEndCommandBuffer` — finish recording a command buffer.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// `command_buffer` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkEndCommandBuffer(_command_buffer: *mut c_void) -> i32 {
    forward_real!(
        "vkEndCommandBuffer",
        unsafe extern "C" fn(*mut c_void) -> i32,
        _command_buffer
    );
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkCmdBeginRenderPass` — begin a render pass instance.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCmdBeginRenderPass(
    _command_buffer: *mut c_void,
    _p_render_pass_begin: *const c_void,
    _contents: i32,
) {
    forward_real!(
        "vkCmdBeginRenderPass",
        unsafe extern "C" fn(*mut c_void, *const c_void, i32),
        _command_buffer,
        _p_render_pass_begin,
        _contents
    );
}

/// `vkCmdEndRenderPass` — end a render pass instance.
///
/// No-op in headless mode.
///
/// # Safety
/// `command_buffer` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCmdEndRenderPass(_command_buffer: *mut c_void) {
    forward_real!(
        "vkCmdEndRenderPass",
        unsafe extern "C" fn(*mut c_void),
        _command_buffer
    );
}

/// `vkCmdDraw` — draw primitives.
///
/// No-op in headless mode.
///
/// # Safety
/// `command_buffer` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCmdDraw(
    _command_buffer: *mut c_void,
    _vertex_count: u32,
    _instance_count: u32,
    _first_vertex: u32,
    _first_instance: u32,
) {
    forward_real!(
        "vkCmdDraw",
        unsafe extern "C" fn(*mut c_void, u32, u32, u32, u32),
        _command_buffer,
        _vertex_count,
        _instance_count,
        _first_vertex,
        _first_instance
    );
}

/// `vkCmdDrawIndexed` — draw indexed primitives.
///
/// No-op in headless mode.
///
/// # Safety
/// `command_buffer` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCmdDrawIndexed(
    _command_buffer: *mut c_void,
    _index_count: u32,
    _instance_count: u32,
    _first_index: u32,
    _vertex_offset: i32,
    _first_instance: u32,
) {
    forward_real!(
        "vkCmdDrawIndexed",
        unsafe extern "C" fn(*mut c_void, u32, u32, u32, i32, u32),
        _command_buffer,
        _index_count,
        _instance_count,
        _first_index,
        _vertex_offset,
        _first_instance
    );
}

/// `vkQueueSubmit` — submit command buffers to a queue.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`; no real queue exists.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkQueueSubmit(
    _queue: *mut c_void,
    _submit_count: u32,
    _p_submits: *const c_void,
    _fence: u64,
) -> i32 {
    forward_real!(
        "vkQueueSubmit",
        unsafe extern "C" fn(*mut c_void, u32, *const c_void, u64) -> i32,
        _queue,
        _submit_count,
        _p_submits,
        _fence
    );
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkQueueWaitIdle` — wait for a queue to become idle.
///
/// Returns `VK_SUCCESS`; no-op in headless mode.
///
/// # Safety
/// `queue` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkQueueWaitIdle(_queue: *mut c_void) -> i32 {
    forward_real!(
        "vkQueueWaitIdle",
        unsafe extern "C" fn(*mut c_void) -> i32,
        _queue
    );
    VK_SUCCESS
}

/// `vkDeviceWaitIdle` — wait for a device to become idle.
///
/// Returns `VK_SUCCESS`; no-op in headless mode.
///
/// # Safety
/// `device` is not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDeviceWaitIdle(_device: *mut c_void) -> i32 {
    forward_real!(
        "vkDeviceWaitIdle",
        unsafe extern "C" fn(*mut c_void) -> i32,
        _device
    );
    VK_SUCCESS
}

// ── Synchronization ───────────────────────────────────────────────────────────

/// `vkCreateFence` — create a new fence object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateFence(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_fence: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateFence",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_fence
    );
    if !p_fence.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_fence.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyFence` — destroy a fence object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyFence(
    _device: *mut c_void,
    _fence: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyFence",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _fence,
        _allocator
    );
}

/// `vkWaitForFences` — wait for one or more fences to become signaled.
///
/// Returns `VK_SUCCESS`; no-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkWaitForFences(
    _device: *mut c_void,
    _fence_count: u32,
    _p_fences: *const u64,
    _wait_all: u32,
    _timeout: u64,
) -> i32 {
    forward_real!(
        "vkWaitForFences",
        unsafe extern "C" fn(*mut c_void, u32, *const u64, u32, u64) -> i32,
        _device,
        _fence_count,
        _p_fences,
        _wait_all,
        _timeout
    );
    VK_SUCCESS
}

/// `vkResetFences` — resets one or more fence objects.
///
/// Returns `VK_SUCCESS`; no-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkResetFences(
    _device: *mut c_void,
    _fence_count: u32,
    _p_fences: *const u64,
) -> i32 {
    forward_real!(
        "vkResetFences",
        unsafe extern "C" fn(*mut c_void, u32, *const u64) -> i32,
        _device,
        _fence_count,
        _p_fences
    );
    VK_SUCCESS
}

/// `vkCreateSemaphore` — create a new semaphore object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateSemaphore(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_semaphore: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateSemaphore",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_semaphore
    );
    if !p_semaphore.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_semaphore.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroySemaphore` — destroy a semaphore object.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroySemaphore(
    _device: *mut c_void,
    _semaphore: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroySemaphore",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _semaphore,
        _allocator
    );
}

// ── Descriptor sets & pipeline layout ────────────────────────────────────────

/// `vkCreateDescriptorSetLayout` — create a new descriptor set layout.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreateDescriptorSetLayout(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_set_layout: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreateDescriptorSetLayout",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_set_layout
    );
    if !p_set_layout.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_set_layout.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyDescriptorSetLayout` — destroy a descriptor set layout.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyDescriptorSetLayout(
    _device: *mut c_void,
    _descriptor_set_layout: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyDescriptorSetLayout",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _descriptor_set_layout,
        _allocator
    );
}

/// `vkCreatePipelineLayout` — create a new pipeline layout object.
///
/// Returns `VK_ERROR_INITIALIZATION_FAILED`.
///
/// # Safety
/// Pointer parameters must be valid or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkCreatePipelineLayout(
    _device: *mut c_void,
    _create_info: *const c_void,
    _allocator: *const c_void,
    p_pipeline_layout: *mut u64,
) -> i32 {
    forward_real!(
        "vkCreatePipelineLayout",
        unsafe extern "C" fn(*mut c_void, *const c_void, *const c_void, *mut u64) -> i32,
        _device,
        _create_info,
        _allocator,
        p_pipeline_layout
    );
    if !p_pipeline_layout.is_null() {
        // SAFETY: caller guarantees valid writable pointer.
        p_pipeline_layout.write(0);
    }
    VK_ERROR_INITIALIZATION_FAILED
}

/// `vkDestroyPipelineLayout` — destroy a pipeline layout.
///
/// No-op in headless mode.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkDestroyPipelineLayout(
    _device: *mut c_void,
    _pipeline_layout: u64,
    _allocator: *const c_void,
) {
    forward_real!(
        "vkDestroyPipelineLayout",
        unsafe extern "C" fn(*mut c_void, u64, *const c_void),
        _device,
        _pipeline_layout,
        _allocator
    );
}

/// `vkGetInstanceProcAddr` — return a function pointer for an instance-level command.
///
/// Returns null; no real Vulkan implementation is present.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetInstanceProcAddr(
    _instance: *mut c_void,
    _name: *const u8,
) -> *const c_void {
    forward_real!(
        "vkGetInstanceProcAddr",
        unsafe extern "C" fn(*mut c_void, *const u8) -> *const c_void,
        _instance,
        _name
    );
    core::ptr::null()
}

/// `vkGetDeviceProcAddr` — return a function pointer for a device-level command.
///
/// Returns null; no real Vulkan implementation is present.
///
/// # Safety
/// Pointer parameters are not meaningfully dereferenced; always safe.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vulkan1_vkGetDeviceProcAddr(
    _device: *mut c_void,
    _name: *const u8,
) -> *const c_void {
    forward_real!(
        "vkGetDeviceProcAddr",
        unsafe extern "C" fn(*mut c_void, *const u8) -> *const c_void,
        _device,
        _name
    );
    core::ptr::null()
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Stub-mode tests (disabled when real_vulkan feature is active) ─────────
    //
    // These tests validate the headless stub behaviour.  When the `real_vulkan`
    // feature is enabled the functions forward to the real ICD loader and the
    // stub return values no longer apply, so the tests are excluded.

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_enumerate_instance_extension_properties_returns_zero_count() {
        let mut count: u32 = 99;
        // SAFETY: count is a valid writable u32.
        let result = unsafe {
            vulkan1_vkEnumerateInstanceExtensionProperties(
                core::ptr::null(),
                &mut count,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, VK_SUCCESS);
        assert_eq!(count, 0);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_enumerate_instance_layer_properties_returns_zero_count() {
        let mut count: u32 = 99;
        // SAFETY: count is a valid writable u32.
        let result = unsafe {
            vulkan1_vkEnumerateInstanceLayerProperties(&mut count, core::ptr::null_mut())
        };
        assert_eq!(result, VK_SUCCESS);
        assert_eq!(count, 0);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_create_instance_fails_and_nulls_out() {
        let mut instance: *mut core::ffi::c_void = 0xDEAD as *mut _;
        // SAFETY: instance is a valid pointer-to-pointer.
        let result = unsafe {
            vulkan1_vkCreateInstance(core::ptr::null(), core::ptr::null(), &mut instance)
        };
        assert_eq!(result, VK_ERROR_INITIALIZATION_FAILED);
        assert!(instance.is_null());
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_enumerate_physical_devices_returns_zero_count() {
        let mut count: u32 = 99;
        // SAFETY: count is a valid writable u32; null instance is handled.
        let result = unsafe {
            vulkan1_vkEnumeratePhysicalDevices(
                core::ptr::null_mut(),
                &mut count,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, VK_SUCCESS);
        assert_eq!(count, 0);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_create_device_fails() {
        let mut device: *mut core::ffi::c_void = 0xBEEF as *mut _;
        // SAFETY: device is a valid pointer-to-pointer.
        let result = unsafe {
            vulkan1_vkCreateDevice(
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                &mut device,
            )
        };
        assert_eq!(result, VK_ERROR_INITIALIZATION_FAILED);
        assert!(device.is_null());
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_queue_wait_idle_succeeds() {
        // SAFETY: null queue; stub does not dereference it.
        let result = unsafe { vulkan1_vkQueueWaitIdle(core::ptr::null_mut()) };
        assert_eq!(result, VK_SUCCESS);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_device_wait_idle_succeeds() {
        // SAFETY: null device; stub does not dereference it.
        let result = unsafe { vulkan1_vkDeviceWaitIdle(core::ptr::null_mut()) };
        assert_eq!(result, VK_SUCCESS);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_wait_for_fences_succeeds() {
        // SAFETY: null parameters; stub does not dereference them.
        let result = unsafe {
            vulkan1_vkWaitForFences(core::ptr::null_mut(), 0, core::ptr::null(), 1, u64::MAX)
        };
        assert_eq!(result, VK_SUCCESS);
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_get_instance_proc_addr_returns_null() {
        // SAFETY: null instance; stub does not dereference it.
        let ptr =
            unsafe { vulkan1_vkGetInstanceProcAddr(core::ptr::null_mut(), core::ptr::null()) };
        assert!(ptr.is_null());
    }

    #[cfg(not(feature = "real_vulkan"))]
    #[test]
    fn test_surface_format_count_returns_zero() {
        let mut count: u32 = 99;
        // SAFETY: count is a valid writable u32.
        let result = unsafe {
            vulkan1_vkGetPhysicalDeviceSurfaceFormatsKHR(
                core::ptr::null_mut(),
                0,
                &mut count,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(result, VK_SUCCESS);
        assert_eq!(count, 0);
    }

    // ── Real-Vulkan mode tests ────────────────────────────────────────────────
    //
    // When the `real_vulkan` feature is active the functions dispatch to the
    // host's ICD loader.  These tests only verify that the dispatch path
    // does not panic or crash; the exact results depend on the host.

    #[cfg(feature = "real_vulkan")]
    #[test]
    fn test_real_vulkan_availability_does_not_panic() {
        // Simply loading the library must not panic or crash.
        let _ = crate::vulkan_loader::is_real_vulkan_available();
    }

    /// When real Vulkan is available, `vkEnumerateInstanceExtensionProperties`
    /// should succeed with a valid (but possibly non-zero) count.  When it is
    /// unavailable the stub returns `VK_SUCCESS` with count zero.
    #[cfg(feature = "real_vulkan")]
    #[test]
    fn test_enumerate_extensions_does_not_crash() {
        let mut count: u32 = 0;
        // SAFETY: count is a valid writable u32; layer_name is null (global).
        let result = unsafe {
            vulkan1_vkEnumerateInstanceExtensionProperties(
                core::ptr::null(),
                &raw mut count,
                core::ptr::null_mut(),
            )
        };
        // Must return a valid VkResult, not an arbitrary garbage value.
        assert!(
            result == VK_SUCCESS || result < 0,
            "unexpected VkResult {result}"
        );
    }
}
