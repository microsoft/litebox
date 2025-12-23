// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_linux_on_windows_userland::CliArgs;
    litebox_runner_linux_on_windows_userland::run(CliArgs::parse())
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
fn main() {
    eprintln!("This program is only supported on Windows x86_64");
    std::process::exit(1);
}
