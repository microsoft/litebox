// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! VM execution substrate, separate from peer-domain authority.
//!
//! `LinuxKernel<H>` owns a host and implements shared kernel mechanisms. The
//! host selects memory/translation resources, time, mutex behavior and execution
//! budget policy. Boot/firmware parsing, device setup and service dispatch are
//! runner responsibilities. VTL gates remain separate capabilities.
//!
//! Additional LiteBox provider traits (CRNG, key derivation, networking, stdio)
//! are implemented on the host only when supported; the kernel delegates them.
//! There are no mandatory SNP-style exits, peer switches, fake networking or
//! allocator-rescue operations in this contract.

use crate::{execution::ExecutionTimer, mm::MemoryProvider};
use litebox::platform::{RawMutexProvider, TimeProvider};

pub trait Host:
    crate::console::DiagnosticOutput + RawMutexProvider + TimeProvider + Sync + 'static
{
    /// Stable resources used by this kernel's base/task page tables.
    type Memory: MemoryProvider;
    type Timer: ExecutionTimer;

    /// This host owns the execution-window policy. No implicit disabled timer;
    /// a debugging host must explicitly choose that behavior.
    fn execution_timer(&self) -> &Self::Timer;
}

#[cfg(feature = "lvbs")]
pub mod lvbs;
#[cfg(test)]
pub mod mock;
pub mod no_scheduler;
mod providers;
