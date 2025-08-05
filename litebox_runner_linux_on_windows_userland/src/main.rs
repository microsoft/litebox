// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use clap::Parser as _;
use litebox_runner_linux_on_windows_userland::CliArgs;

fn main() -> anyhow::Result<()> {
    litebox_runner_linux_on_windows_userland::run(CliArgs::parse())
}
