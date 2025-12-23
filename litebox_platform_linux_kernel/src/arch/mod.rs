// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Arch-specific code

#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "x86_64")]
pub use x86::*;
