// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner for [`litebox_syscall_rewriter`]

use clap::{Parser, ValueEnum};
use std::io::Read as _;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

/// Rewrite ELF files to hook syscalls, or PE files to hook syscalls and change GS TEB accesses to FS.
#[derive(Parser, Debug)]
struct CliArgs {
    /// Path to input binary
    input_binary: PathBuf,
    /// Path to output the generated binary (default = <INPUT_BINARY>.hooked)
    #[arg(short = 'o', long = "output")]
    output_binary: Option<PathBuf>,
    /// Absolute address to set in the trampoline (default = 0)
    #[arg(long)]
    trampoline_addr: Option<u64>,
    /// Host operating system that will run the rewritten guest
    #[arg(long, value_enum, default_value_t)]
    target_host: CliTargetHost,
    /// Virtualize the AArch64 guest's x18 register
    #[arg(long)]
    virtualize_x18: bool,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum CliTargetHost {
    #[default]
    Linux,
    Macos,
    Windows,
}

impl CliArgs {
    fn rewrite_options(&self) -> litebox_syscall_rewriter::RewriteOptions {
        let target_host = match self.target_host {
            CliTargetHost::Linux => litebox_syscall_rewriter::TargetHost::Linux,
            CliTargetHost::Macos => litebox_syscall_rewriter::TargetHost::MacOs,
            CliTargetHost::Windows => litebox_syscall_rewriter::TargetHost::Windows,
        };
        litebox_syscall_rewriter::RewriteOptions::new(target_host, self.virtualize_x18)
    }
}

fn copy_file_permissions(
    input_file: &std::fs::File,
    output_file: &std::fs::File,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        output_file.set_permissions(std::fs::Permissions::from_mode(
            input_file.metadata()?.mode(),
        ))?;
    }
    #[cfg(windows)]
    {
        let input_metadata = input_file.metadata()?;
        let perms = input_metadata.permissions();
        output_file.set_permissions(perms)?;
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli_args = CliArgs::parse();
    let mut input_binary = std::fs::File::open(&cli_args.input_binary)?;
    let mut input_binary_bytes = vec![];
    input_binary.read_to_end(&mut input_binary_bytes)?;
    let output_binary = litebox_syscall_rewriter::rewrite_binary_with_options(
        &input_binary_bytes,
        cli_args.trampoline_addr,
        cli_args.rewrite_options(),
    )?;
    let output_path = cli_args.output_binary.unwrap_or_else(|| {
        cli_args.input_binary.with_file_name(
            cli_args
                .input_binary
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                + ".hooked",
        )
    });
    let mut file = std::fs::File::create(output_path)?;
    copy_file_permissions(&input_binary, &file)?;
    file.write_all(&output_binary)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_rewrite_options_parse_matrix() {
        for (args, expected_host, add_x18_flag, expected_x18) in [
            (
                vec!["rewriter", "input"],
                litebox_syscall_rewriter::TargetHost::Linux,
                false,
                false,
            ),
            (
                vec!["rewriter", "input", "--target-host", "linux"],
                litebox_syscall_rewriter::TargetHost::Linux,
                false,
                false,
            ),
            (
                vec!["rewriter", "input", "--target-host", "macos"],
                litebox_syscall_rewriter::TargetHost::MacOs,
                true,
                true,
            ),
            (
                vec!["rewriter", "input", "--target-host", "windows"],
                litebox_syscall_rewriter::TargetHost::Windows,
                false,
                true,
            ),
        ] {
            let mut args = args;
            if add_x18_flag {
                args.push("--virtualize-x18");
            }
            let options = CliArgs::try_parse_from(args).unwrap().rewrite_options();
            assert_eq!(options.target_host(), expected_host);
            assert_eq!(options.effective_virtualize_x18(), expected_x18);
        }
    }
}
