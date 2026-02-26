// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use clap::Parser;
use litebox_runner_macos_on_linux_userland::{CliArgs, run};

fn main() -> anyhow::Result<()> {
    run(CliArgs::parse())
}
