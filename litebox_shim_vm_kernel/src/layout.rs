// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The kernel-laid-out part of a process, at the top of the user address
//! space. Checked at compile time: regions are page-aligned, sorted, disjoint,
//! and in [`RUNNER_MANAGED_MAX`]..[`USER_END`]. Gaps stay unmapped as guards.

use litebox_broker_protocol::shared_buffer::SHARED_BUFFER_POOL_SIZE;
use litebox_common_vm_abi::{PAGE_SIZE, RUNNER_MANAGED_MAX, USER_END, UserRegion};

const MIB: u64 = 1 << 20;

const BASE: u64 = RUNNER_MANAGED_MAX;

/// The runner is loaded at its start (see `loader`).
pub const RUNNER_IMAGE: UserRegion = UserRegion {
    start: BASE,
    len: 256 * MIB,
};

pub const STARTUP_INFO: UserRegion = UserRegion {
    start: BASE + 0x1000_0000,
    len: PAGE_SIZE,
};

pub const UPCALL_STACK: UserRegion = UserRegion {
    start: BASE + 0x1010_0000,
    len: 64 * 1024,
};

pub const STACK: UserRegion = UserRegion {
    start: BASE + 0x1100_0000,
    len: MIB,
};

pub const MESSAGE_WINDOW: UserRegion = UserRegion {
    start: BASE + 0x2000_0000,
    len: 16 * MIB,
};

pub const BROKER_SHARED_MEMORY: UserRegion = UserRegion {
    start: BASE + 0x3000_0000,
    len: SHARED_BUFFER_POOL_SIZE as u64,
};

/// Bounds the images' total size.
pub const IMAGES: UserRegion = UserRegion {
    start: BASE + 0x4000_0000,
    len: 1024 * MIB,
};

pub const HEAP: UserRegion = UserRegion {
    start: BASE + 0x8000_0000,
    len: 256 * MIB,
};

const _: () = {
    let regions = [
        RUNNER_IMAGE,
        STARTUP_INFO,
        UPCALL_STACK,
        STACK,
        MESSAGE_WINDOW,
        BROKER_SHARED_MEMORY,
        IMAGES,
        HEAP,
    ];
    let mut i = 0;
    while i < regions.len() {
        assert!(
            regions[i].start.is_multiple_of(PAGE_SIZE) && regions[i].len.is_multiple_of(PAGE_SIZE)
        );
        assert!(RUNNER_MANAGED_MAX <= regions[i].start && regions[i].end() <= USER_END);
        if i > 0 {
            assert!(regions[i - 1].end() <= regions[i].start);
        }
        i += 1;
    }
};
