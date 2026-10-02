// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/x86_64_qemu.ld");
    println!("cargo::rustc-link-arg-bins=--script={script}");
    // Cargo does not track the linker script, as it is not a Rust source.
    println!("cargo::rerun-if-changed=x86_64_qemu.ld");
}
