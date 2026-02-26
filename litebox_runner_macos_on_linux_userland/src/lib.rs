// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run macOS x86_64 Mach-O programs with LiteBox on Linux.

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use litebox_shim_bsd::RuntimeFileResolver;
use memmap2::Mmap;
use std::collections::BTreeMap;
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
    /// Add a runtime file mapping as `guest_path=host_path` (e.g. `/dyld-litebox=./dyld_stub_macos`)
    #[arg(long = "runtime-file")]
    pub runtime_files: Vec<String>,
}

struct RuntimeFiles {
    files: BTreeMap<String, &'static [u8]>,
}

impl RuntimeFiles {
    fn from_cli(entries: &[String]) -> Result<Self> {
        let mut files = BTreeMap::new();
        for entry in entries {
            let (guest_path, host_path) = entry.split_once('=').ok_or_else(|| {
                anyhow!("Invalid --runtime-file value '{entry}', expected guest=host")
            })?;
            if guest_path.is_empty() || !guest_path.starts_with('/') {
                anyhow::bail!("Invalid guest runtime path '{guest_path}', expected absolute path");
            }
            files.insert(guest_path.to_string(), mmapped_file_data(host_path)?);
        }
        Ok(Self { files })
    }
}

impl RuntimeFileResolver for RuntimeFiles {
    fn read_file(&self, path: &str) -> Option<&[u8]> {
        self.files.get(path).copied()
    }
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
    let runtime_files = RuntimeFiles::from_cli(&cli_args.runtime_files)?;

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
    let program = shim.load_program_with_runtime_files(binary_data, argv, envp, &runtime_files)?;

    // Run the program
    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    std::process::exit(0)
}
