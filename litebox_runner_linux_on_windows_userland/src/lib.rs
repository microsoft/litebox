// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use std::path::PathBuf;

/// Run Linux programs with LiteBox on unmodified Windows.
///
/// The program binary and all its dependencies (including `litebox_rtld_audit.so`)
/// must be provided inside a tar archive via `--initial-files`. The program path
/// refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the tar archive provided via
    /// `--initial-files`. All binaries must be pre-rewritten with the syscall
    /// rewriter and the tar must include `litebox_rtld_audit.so`.
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs; can be invoked multiple times)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
    /// Forward the existing environment variables
    #[arg(long = "forward-env")]
    pub forward_environment_variables: bool,
    /// Allow using unstable options
    #[arg(short = 'Z', long = "unstable")]
    pub unstable: bool,
    /// Tar archive containing the program, its shared libraries, and litebox_rtld_audit.so.
    ///
    /// All ELF binaries should be pre-rewritten with the syscall rewriter
    /// (e.g., via `litebox-packager`).
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
}

/// Run Linux programs with LiteBox on unmodified Windows
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    let platform = Platform::new();
    litebox_platform_multiplex::set_platform(platform);
    let mut shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &cli_args.program_and_arguments[0];

    let initial_file_system = {
        let in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
        shim_builder.default_fs(in_mem, tar_ro)
    };
    shim_builder.set_fs(initial_file_system);

    shim_builder.set_load_filter(fixup_env);
    let shim = shim_builder.build();
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    };

    let program = shim
        .load_program(platform.init_task(), prog_path, argv, envp)
        .unwrap();
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    std::process::exit(program.process.wait())
}

fn fixup_env(envp: &mut Vec<alloc::ffi::CString>) {
    // Always inject LD_AUDIT so the dynamic linker loads the audit library
    // that sets up trampolines for rewritten binaries.
    let p = c"LD_AUDIT=/lib/litebox_rtld_audit.so";
    let has_ld_audit = envp.iter().any(|var| var.as_c_str() == p);
    if !has_ld_audit {
        envp.push(p.into());
    }
}
