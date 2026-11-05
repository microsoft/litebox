// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! `containerd-shim-litebox-v1`, the containerd shim of LiteBox (see the library).

#[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    litebox_containerd_shim::main();
}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))))]
fn main() {
    eprintln!("containerd-shim-litebox-v1 requires Linux or AArch64 macOS");
    std::process::exit(1);
}
