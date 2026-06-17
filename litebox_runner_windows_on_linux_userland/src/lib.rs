// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Linux. For now, we are restricting this to only x86-64
// Linux, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Context as _, Result};
use clap::Parser;
use litebox_platform_linux_userland::LinuxUserland;
use std::path::PathBuf;

/// Run Windows PE programs with LiteBox on unmodified Linux.
///
/// The program binary and any initial filesystem contents must be provided inside a tar archive via
/// `--initial-files`. The program path refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/app/program.exe --help`).
    ///
    /// The program path refers to a path inside the tar archive provided via `--initial-files`.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times).
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables.
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options.
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Tar archive containing the program and its runtime files.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
}

/// Run Windows PE programs with LiteBox on unmodified Linux.
///
/// # Panics
///
/// Panics if the initial in-memory file system fails to create `/tmp` - those
/// operations cannot fail against a freshly-constructed file system.
pub fn run(cli_args: CliArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    if cli_args.unstable {
        litebox_util_log::warn!(
            "Windows PE on Linux runner is currently a skeleton; shim functionality is not implemented yet"
        );
    }

    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .with_context(|| format!("Could not read tar file at {}", tar_file.display()))?;

    let platform = LinuxUserland::new(None);
    let shim_builder = litebox_shim_windows::WindowsShimBuilder::new(platform);
    let litebox = shim_builder.litebox();

    let (program_path, program_args) = cli_args
        .program_and_arguments
        .split_first()
        .context("program path missing - clap should have required at least one argument")?;

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .expect("/tmp creation cannot fail on a fresh in-memory file system");
            fs.chown("/tmp", Some(1000), Some(1000))
                .expect("/tmp chown cannot fail on a fresh in-memory file system");
        });

        let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
        shim_builder.default_fs(in_mem, tar_ro)
    };
    let initial_file_system = std::sync::Arc::new(initial_file_system);

    let shim = shim_builder.build();
    let argv = std::iter::once(program_path.as_str())
        .chain(program_args.iter().map(String::as_str))
        .map(to_cstring)
        .collect::<Result<Vec<_>>>()
        .context("argv contained an interior NUL byte")?;
    let mut envp = cli_args
        .environment_variables
        .iter()
        .map(|s| to_cstring(s))
        .collect::<Result<Vec<_>>>()
        .context("--env value contained an interior NUL byte")?;
    if cli_args.forward_environment_variables {
        for (key, value) in std::env::vars() {
            envp.push(
                to_cstring(&format!("{key}={value}"))
                    .context("forwarded environment variable contained an interior NUL byte")?,
            );
        }
    }

    let program = shim
        .load_program(initial_file_system, program_path, argv, envp)
        .context("failed to load Windows PE program")?;
    // SAFETY: `WindowsShimEntrypoints::init` populates `rip`/`rsp`/`eflags` inside
    // `run_thread` before the initial guest thread executes, so the `PtRegs::default()`
    // we hand in is fully initialized before any guest instruction runs.
    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    std::process::exit(program.process.wait())
}

fn to_cstring(s: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(Into::into)
}
