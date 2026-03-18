// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

fn main() -> anyhow::Result<()> {
    use clap::Parser as _;
    use litebox_packager::CliArgs;
    litebox_packager::run(CliArgs::parse())
}
