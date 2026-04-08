// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! A sandboxed tool executor built on LiteBox.
//!
//! On Windows, runs Linux commands inside LiteBox in-process, capturing
//! stdout, stderr, exit code, and a structured syscall audit trail.
//! On Linux, the CLI spawns `litebox_runner_linux_userland` as a subprocess
//! (see `main.rs`); this library provides shared protocol types.

pub mod protocol;

// The in-process execute() function is Windows-only — it uses the Windows
// userland platform directly. On Linux, the main binary delegates to
// litebox_runner_linux_userland as a subprocess instead.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
mod windows_executor;

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub use windows_executor::execute;
