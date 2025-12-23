// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use clap::Parser as _;
use litebox_runner_optee_on_linux_userland::CliArgs;

fn main() -> anyhow::Result<()> {
    litebox_runner_optee_on_linux_userland::run(CliArgs::parse())
}
