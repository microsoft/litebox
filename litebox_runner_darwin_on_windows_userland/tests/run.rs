// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! End-to-end runs of the Mach-O programs in `litebox_shim_darwin/test-bins/`.

#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

const RUNNER: &str = env!("CARGO_BIN_EXE_litebox_runner_darwin_on_windows_userland");

include!("../../litebox_shim_darwin/test-bins/end_to_end.rs");
