// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    let status =
        litebox_runner_macos_userland::run(litebox_runner_macos_userland::CliArgs::parse())?;
    std::process::exit(status);
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("litebox_runner_macos_userland requires Apple Silicon macOS");
    std::process::exit(1);
}
