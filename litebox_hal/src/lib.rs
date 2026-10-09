// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Hardware abstraction layer for LiteBox kernel-mode runners: what a VM
//! cannot do by itself and gets from its (virtual) hardware or hypervisor.
//! Each module states the hardware it assumes. Runners choose and wire the
//! sources.

#![no_std]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

#[cfg(target_arch = "x86_64")]
pub mod clock;
#[cfg(target_arch = "x86_64")]
pub mod console;
pub mod dma;
#[cfg(target_arch = "x86_64")]
pub mod interrupt;
#[cfg(target_arch = "x86_64")]
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod power;
pub mod prk;
#[cfg(target_arch = "x86_64")]
pub mod rng;
#[cfg(target_arch = "x86_64")]
pub mod timer;
#[cfg(target_arch = "x86_64")]
pub mod virtio;
