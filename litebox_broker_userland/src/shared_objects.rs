// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host-file-backed storage for the broker's in-memory files.
//!
//! Linux uses memfds and Windows uses temporary files. Both providers access contents through
//! positional I/O, including staged copies for buffers that cannot expose their bytes directly.
//! Requesting an object and delivering it to a runner are separate from creating its storage.

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
mod host_file;

/// Memfd-backed shared file memory for Linux.
#[cfg(target_os = "linux")]
pub mod linux;

/// Temporary-file-backed shared file memory for Windows.
///
/// Pagefile-backed sections cannot grow, so file contents live in temporary files that are
/// deleted when their storage closes. A later deployment may derive sections from these files.
#[cfg(all(windows, target_arch = "x86_64"))]
pub mod windows;
