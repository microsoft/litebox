// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Serves one OP-TEE TA instance in ring 3 on the LiteBox VM kernel.
//!
//! - The kernel runs one instance per process and ends the process when the
//!   instance ends.
//! - The TA and `ldelf` may be syscall-rewritten (syscalls are calls into the
//!   shim) or unmodified (each `syscall` costs one kernel round trip).
//! - Process entry, heap, and panics: `litebox_platform_vm_userland::start`.

#![cfg(target_arch = "x86_64")]
#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

extern crate alloc;

mod optee;

litebox_platform_vm_userland::entry!(optee::serve);
