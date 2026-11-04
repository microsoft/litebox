// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd shim of LiteBox (see the library).

#[cfg(target_os = "linux")]
fn main() {
    litebox_containerd_shim::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("containerd-shim-litebox-v1 runs on Linux only");
    std::process::exit(1);
}
