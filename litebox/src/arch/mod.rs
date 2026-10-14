// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Architecture-specific helpers independent of host operating systems and guest ABIs.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;
