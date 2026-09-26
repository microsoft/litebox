// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! This module contains the loader for the LiteBox shim.
//!
//! Nothing in here is architecture-specific: segment mapping, the auxiliary
//! vector and the initial stack layout are all defined by the generic
//! System V/Linux ABI, and the ELF machine type is carried by the image rather
//! than assumed. The module is therefore built for every architecture the rest
//! of the shim supports, so an aarch64 host gets the same loader an x86-64 host
//! does.

pub mod auxv;
pub mod elf;
mod stack;

pub(crate) const DEFAULT_STACK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// A default low address is used for the binary (which grows upwards) to avoid
/// conflicts with the kernel's memory mappings (which grows downwards).
///
/// This is a preference, not a floor. Use [`default_low_addr`] rather than the
/// constant directly: on a host whose lowest mappable address is higher than
/// this, asking for it is not merely ignored but rejected.
pub(crate) const DEFAULT_LOW_ADDR: usize = 0x1000_0000;

/// [`DEFAULT_LOW_ADDR`], raised to the host's lowest mappable address.
///
/// An arm64 Mach-O process reserves the first 4 GiB as `__PAGEZERO`, which puts
/// `TASK_ADDR_MIN` above the constant. A mapping requested below that floor
/// fails with `BelowMinAddress`, surfaced to the guest as `EPERM`, so on such a
/// host the bare constant makes every image -- including a
/// position-independent one, which is otherwise free to land anywhere -- fail
/// to load.
pub(crate) fn default_low_addr<Platform: crate::ShimPlatform>() -> usize {
    DEFAULT_LOW_ADDR.max(
        <Platform as litebox::platform::PageManagementProvider<
            { litebox::mm::vmem::PAGE_SIZE },
        >>::TASK_ADDR_MIN,
    )
}
