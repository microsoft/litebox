// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Kernels link with the script at `DEP_LITEBOX_BOOTLOADER_LINKER_SCRIPT`.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("set by Cargo");
    println!("cargo::metadata=linker_script={dir}/x86_64_kernel.ld");
    println!("cargo::rerun-if-changed=build.rs");
}
