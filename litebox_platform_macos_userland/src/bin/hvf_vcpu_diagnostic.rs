// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// `src/bin/*.rs` files are their own crate roots, so the library's
// `#![cfg(all(target_os = "macos", target_arch = "aarch64"))]` gate doesn't
// apply here: it only empties the library on other hosts, it doesn't stop
// this binary from being built. Gate `main` explicitly instead, matching
// `litebox_runner_linux_on_macos_userland`'s binary.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    match litebox_platform_macos_userland::hvf_vcpu_diagnostic_probe() {
        Ok(report) => println!("{report:#?}"),
        Err(error) => {
            eprintln!("HVF vCPU production diagnostic failed: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("This program is only supported on macOS on Apple Silicon");
    std::process::exit(1);
}
