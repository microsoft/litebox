// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd shim of LiteBox (see the library).

#[cfg(any(target_os = "linux", all(windows, target_arch = "x86_64")))]
fn main() {
    litebox_containerd_shim::main();
}

#[cfg(not(any(target_os = "linux", all(windows, target_arch = "x86_64"))))]
fn main() {
    eprintln!("containerd-shim-litebox-v1 runs on Linux and Windows x86-64 only");
    std::process::exit(1);
}
