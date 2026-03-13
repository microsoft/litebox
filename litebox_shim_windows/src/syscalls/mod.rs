// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Windows syscall interface
//!
//! This module provides the Windows NTDLL syscall interface for Phase 2.
//! It includes file I/O, console I/O, and memory management APIs.

pub mod ntdll;

pub use ntdll::{ConsoleHandle, FileHandle, NtdllApi};
