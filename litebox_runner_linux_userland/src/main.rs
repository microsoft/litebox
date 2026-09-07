// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use clap::Parser as _;
use litebox_runner_linux_userland::CliArgs;

fn main() -> anyhow::Result<()> {
    let exit_code = litebox_runner_linux_userland::run(CliArgs::parse())?;
    std::process::exit(exit_code)
}
