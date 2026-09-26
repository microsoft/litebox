// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-testable boot-memory policy for the QEMU debugging runner.
//! This is not a production platform or a general firmware framework. This
//! runner boots and tests shared kernel mechanisms and finite ring-3 payloads.
//! OP-TEE dispatch, transport, device interrupts/timers, and scheduling are not
//! implemented here yet.
//! Run `python3 litebox_runner_optee_on_kvm/scripts/run.py --negative-tests`
//! from the workspace root (QEMU and the pinned nightly with rust-src required).
#![no_std]

pub mod memory_map;
