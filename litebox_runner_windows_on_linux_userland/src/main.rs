// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_runner_windows_on_linux_userland::CliArgs;
    litebox_runner_windows_on_linux_userland::run(CliArgs::parse())
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn main() {
    eprintln!("This program is only supported on Linux x86_64");
    std::process::exit(1);
}
