// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The LVBS binary owns its global heap. Platform memory operations are bound
//! to this same instance before the runner hands over any boot memory.

use litebox_platform_lvbs::host::lvbs::memory::{LvbsAllocator, install_allocator};

#[global_allocator]
static ALLOCATOR: LvbsAllocator = LvbsAllocator::new();

pub(crate) fn install() {
    install_allocator(&ALLOCATOR).expect("the BSP must install the LVBS allocator exactly once");
}
