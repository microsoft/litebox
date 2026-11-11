// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files.

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file;

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux;

/// Temporary-file-backed shared file memory for Windows.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
