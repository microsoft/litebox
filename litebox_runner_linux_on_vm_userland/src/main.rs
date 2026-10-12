// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs one Linux program in ring 3 on the LiteBox VM kernel.
//!
//! - The kernel runs one program per process, and ends the process once the
//!   program's exit status is in.
//! - The program's syscalls are calls into the shim: it may be
//!   syscall-rewritten, or else the shim patches it as it loads it. Only a
//!   `syscall` the shim cannot patch, e.g., in code generated at run time,
//!   costs a kernel round trip (the kernel reflects it).
//! - Process entry, heap, and panics: `litebox_platform_vm_userland::start`.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod linux;

litebox_platform_vm_userland::entry!(linux::serve);
