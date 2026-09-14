// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Result, bail};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "AArch64 Linux runner for macOS; broker support is required")]
pub struct CliArgs {
    /// Program and its arguments; host path unless --program-from-tar is set.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Guest environment variable, KEY=VALUE.
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the host environment.
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Enable unstable runner options.
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Uncompressed tar containing the Linux interpreter, libraries and files.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Resolve the absolute program path within --initial-files.
    #[arg(long = "program-from-tar", requires_all = ["unstable", "initial_files"], help_heading = "Unstable Options")]
    pub program_from_tar: bool,
}

/// Returns an error until the macOS runner can connect to a broker.
pub fn run(cli_args: CliArgs) -> Result<i32> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let _ = cli_args;
    bail!("filesystem startup on macOS requires broker support")
}
