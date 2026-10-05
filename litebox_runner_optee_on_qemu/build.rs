// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() {
    let script = std::env::var("DEP_LITEBOX_BOOTLOADER_LINKER_SCRIPT")
        .expect("litebox_bootloader provides its linker script");
    println!("cargo::rustc-link-arg-bins=--script={script}");
    // Cargo does not track the linker script, as it is not a Rust source.
    println!("cargo::rerun-if-changed={script}");
}
