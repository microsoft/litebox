// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs external compatibility test suites natively and under LiteBox, and reports where LiteBox
//! passes and fails.

mod exec;
mod litebox;
mod ltp;
mod report;

use anyhow::{Context as _, Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};
use xshell::{Shell, cmd};

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the Linux Test Project (LTP) suite.
    Ltp(ltp::LtpArgs),
    /// Compare two runs' results.
    Compare {
        /// The earlier run: its results.json or its output directory.
        old: PathBuf,
        /// The later run: its results.json or its output directory.
        new: PathBuf,
    },
}

/// Options shared by every suite.
#[derive(Debug, Args)]
struct CommonArgs {
    /// Also run every test natively on the host, as a baseline.
    #[arg(long)]
    native: bool,
    /// Run under LiteBox without the broker's (unstable) process-duplication support, which
    /// otherwise lets guests fork.
    #[arg(long)]
    no_fork: bool,
    /// Number of tests to run concurrently [default: available parallelism].
    #[arg(short, long)]
    jobs: Option<usize>,
    /// Per-test timeout in seconds, raised for tests that declare longer timeouts or runtimes.
    #[arg(long, default_value_t = 120)]
    timeout: u64,
    /// Build and run LiteBox in release mode.
    #[arg(long)]
    release: bool,
    /// Directory for results.json, report.md and logs [default: under the Cargo target
    /// directory, in compat_scanner/runs/].
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

/// Locations shared by every suite.
struct Workspace {
    root: PathBuf,
    cargo_target: PathBuf,
}

impl Workspace {
    fn locate() -> Result<Self> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .context("compat_scanner is expected at <workspace>/dev_tools/compat_scanner")?
            .to_path_buf();
        let sh = Shell::new()?;
        sh.change_dir(&root);
        let metadata = cmd!(sh, "cargo metadata --format-version 1 --no-deps")
            .quiet()
            .read()?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
        let cargo_target = PathBuf::from(
            metadata["target_directory"]
                .as_str()
                .context("cargo metadata has no target_directory")?,
        );
        Ok(Self { root, cargo_target })
    }

    /// The scanner's directory inside the Cargo target directory, which holds fetched suites,
    /// packaged root file systems, and runs.
    fn scratch(&self) -> PathBuf {
        self.cargo_target.join("compat_scanner")
    }

    /// The checked-out LiteBox commit, marked `-dirty` if the tree has local changes.
    fn litebox_commit(&self) -> String {
        let Ok(sh) = Shell::new() else {
            return "unknown".into();
        };
        sh.change_dir(&self.root);
        let Ok(head) = cmd!(sh, "git rev-parse HEAD").quiet().read() else {
            return "unknown".into();
        };
        let dirty = cmd!(sh, "git status --porcelain")
            .quiet()
            .read()
            .is_ok_and(|status| !status.is_empty());
        if dirty { format!("{head}-dirty") } else { head }
    }
}

#[cfg(not(target_os = "linux"))]
compile_error!("compat_scanner runs Linux test suites, so it only supports Linux hosts");

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Ltp(args) => {
            require_tools(&[
                "cargo", "cc", "curl", "kill", "ldd", "make", "setsid", "sh", "tar", "xz",
            ])?;
            ltp::run(&Workspace::locate()?, &args)
        }
        Command::Compare { old, new } => report::compare(&old, &new),
    }
}

/// Fails unless every one of `tools` is on `PATH`.
fn require_tools(tools: &[&str]) -> Result<()> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let missing: Vec<_> = tools
        .iter()
        .filter(|tool| !std::env::split_paths(&path).any(|dir| dir.join(tool).is_file()))
        .collect();
    if !missing.is_empty() {
        bail!("compat_scanner needs these programs, which are not on PATH: {missing:?}");
    }
    Ok(())
}
