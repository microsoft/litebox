// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
extern crate alloc;

#[cfg(target_os = "none")]
mod boot;
#[cfg(target_os = "none")]
mod guest;

#[cfg(not(target_os = "none"))]
fn main() {
    eprintln!("This debugging runner boots as a VM kernel. Use scripts/run.py.");
    std::process::exit(2);
}
