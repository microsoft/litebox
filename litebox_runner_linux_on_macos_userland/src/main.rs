// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restricted to Apple Silicon macOS: see the crate docs for why there is no
// x86-64 variant.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_linux_on_macos_userland::CliArgs;
    litebox_runner_linux_on_macos_userland::run(CliArgs::parse())
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("This program is only supported on macOS on Apple Silicon");
    std::process::exit(1);
}
