// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Linux, as it relies on `ldd` for
// dependency discovery and other Linux-specific functionality.

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_packager::CliArgs;
    litebox_packager::run(CliArgs::parse())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This program is only supported on Linux");
    std::process::exit(1);
}
