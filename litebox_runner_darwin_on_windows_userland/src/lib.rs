// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// The Darwin shim runs x86-64 Mach-O guests, which this host can only execute
// natively on x86-64 Windows.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

use anyhow::{Context as _, Result};
use clap::Parser;
use litebox_platform_windows_userland::WindowsUserland;
use std::path::PathBuf;

/// Run x86-64 macOS (Mach-O) programs with LiteBox on unmodified Windows.
///
/// Only programs that need no dynamic linker can run: dyld and Apple's system
/// libraries cannot be redistributed, so a program linked against `libSystem`
/// (as nearly every macOS program is) is refused at load time.
///
/// The program binary and any initial filesystem contents must be provided inside a tar archive via
/// `--initial-files`. The program path refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/hello --help`).
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
    /// Tar archive containing the program and its runtime files.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
}

/// Run a Mach-O program with LiteBox on unmodified Windows, then exit with its
/// status.
///
/// # Errors
///
/// Fails if the tar archive cannot be read or the program cannot be loaded.
///
/// # Panics
///
/// Panics if the initial in-memory file system fails to create `/tmp` - those
/// operations cannot fail against a freshly-constructed file system.
pub fn run(cli_args: CliArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .with_context(|| format!("Could not read tar file at {}", tar_file.display()))?;

    let platform = WindowsUserland::new();
    let shim_builder = litebox_shim_darwin::DarwinShimBuilder::new(platform);

    let (program_path, program_args) = cli_args
        .program_and_arguments
        .split_first()
        .context("program path missing - clap should have required at least one argument")?;

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(shim_builder.litebox());
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .expect("/tmp creation cannot fail on a fresh in-memory file system");
        });
        shim_builder.default_fs(in_mem, tar_data.into())
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
        .context("failed to load Mach-O program")?;
    // SAFETY: `DarwinShimEntrypoints::init` sets every register the guest starts
    // with inside `run_thread`, before the first guest instruction runs.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    std::process::exit(program.process.wait())
}

fn to_cstring(s: &str) -> Result<std::ffi::CString> {
    std::ffi::CString::new(s.as_bytes()).map_err(Into::into)
}
