// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Runners link with this crate's script, from `DEP_LITEBOX_PLATFORM_VM_USERLAND_LINKER_SCRIPT`.
fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("set by Cargo");
    println!("cargo::metadata=linker_script={dir}/x86_64_vm_userland.ld");
    println!("cargo::rerun-if-changed=build.rs");
}
