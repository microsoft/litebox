// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-testable boot-memory policy for the QEMU debugging runner.
//! This is not a production platform or a general firmware framework. This
//! runner tests shared kernel mechanisms, finite ring-3 payloads, and real
//! OP-TEE ldelf/hello TA lifecycles through litebox_shim_optee. Both existing
//! hello fixtures (two/three load segments) must return verified command values.
//! Transport, device interrupts/timers, and scheduling are not implemented.
//! Run `python3 litebox_runner_optee_on_kvm/scripts/run.py --negative-tests`
//! from the workspace root (QEMU and the pinned nightly with rust-src required).
#![no_std]

pub mod memory_map;
