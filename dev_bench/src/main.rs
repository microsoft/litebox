#![allow(unused_imports)]

use anyhow::{Result, anyhow};
use clap::Parser;
use fs_err as fs;
use std::path::PathBuf;
use tracing::{debug, error, info, trace, warn};

/// Finds and switches to the project root directory.
///
/// This is to make the rest of the reasoning easier.
pub(crate) fn project_root() -> Result<PathBuf> {
    let mut dir = std::env::current_dir().ok().unwrap();
    loop {
        if dir.join("target").is_dir() {
            std::env::set_current_dir(&dir)?;
            info!(dir = %dir.display(), "Changed working directory to project root");
            return Ok(dir);
        }
        if !dir.pop() {
            return Err(anyhow!("Could not find project root"));
        }
    }
}

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    /// Increase verbosity (pass multiple times to increase)
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() -> Result<()> {
    let cli_args = CliArgs::parse();
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_max_level(match cli_args.verbose {
            0 => tracing::Level::INFO,
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        })
        .init();
    if cli_args.verbose > 2 {
        warn!(
            verbosity = cli_args.verbose,
            "Too much verbosity, capping to TRACE (equivalent to -vv)"
        );
    }
    debug!(cli_args.verbose);

    project_root()?;

    println!("Hello, world!");
    Ok(())
}
