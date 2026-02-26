// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run macOS x86_64 Mach-O programs with LiteBox on Linux.

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::path::Path;

extern crate alloc;

/// Run macOS x86_64 Mach-O programs with LiteBox on Linux.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it
    #[arg(required = true, trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
    pub program_and_arguments: Vec<String>,
    /// Environment variables passed to the program (`K=V` pairs)
    #[arg(long = "env")]
    pub environment_variables: Vec<String>,
}

fn mmapped_file_data(path: impl AsRef<Path>) -> Result<&'static [u8]> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)?;
    // SAFETY: We assume that the file given to us is not going to change externally while in
    // the middle of execution. Since we are mapping it as read-only and mapping it only once,
    // we are not planning to change it either.
    //
    // We need to leak the `Mmap` object, so that it stays alive until the end of the program.
    Ok(Box::leak(Box::new(unsafe { Mmap::map(&file) }.map_err(
        |e| anyhow!("Could not memory-map file at {}: {}", path.display(), e),
    )?)))
}

/// Run macOS x86_64 Mach-O programs with LiteBox on Linux.
pub fn run(cli_args: CliArgs) -> Result<()> {
    // Memory-map the binary file
    let binary_data = mmapped_file_data(&cli_args.program_and_arguments[0])?;

    // Initialize the platform
    let platform = Platform::new(None);
    litebox_platform_multiplex::set_platform(platform);

    // Build the shim
    let shim = litebox_shim_bsd::BsdShimBuilder::new().build();

    // Build argv and envp
    let argv: Vec<_> = cli_args
        .program_and_arguments
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect();

    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|s| std::ffi::CString::new(s.as_bytes()).unwrap())
        .collect();

    // Load the program
    let program = shim.load_program(binary_data, argv, envp)?;

    // Run the program
    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    std::process::exit(0)
}
