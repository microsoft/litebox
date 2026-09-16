// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runner for [`litebox_syscall_rewriter`]

use clap::{Parser, ValueEnum};
use std::io::Read as _;
use std::io::Write as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::PathBuf;

/// Rewrite ELF or AArch64 Mach-O syscall/TLS accesses, or PE syscalls and GS TEB accesses.
#[derive(Parser, Debug)]
#[command(arg_required_else_help = true)]
struct CliArgs {
    /// Path to input binary
    input_binary: PathBuf,
    /// Path to output the generated binary (default = <INPUT_BINARY>.hooked)
    #[arg(short = 'o', long = "output")]
    output_binary: Option<PathBuf>,
    /// Absolute address to set in the trampoline (default = 0)
    #[arg(long)]
    trampoline_addr: Option<u64>,
    /// Host TLS ABI for AArch64 gates (default: ELF=linux, Mach-O=macos, PE=windows)
    #[arg(long, value_enum)]
    target_host: Option<CliTargetHost>,
    /// AArch64 ELF only: virtualize guest x18 on Linux (development/testing)
    #[arg(long)]
    virtualize_x18: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliTargetHost {
    Linux,
    Macos,
    Windows,
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
    let host = match cli_args.target_host {
        Some(CliTargetHost::Linux) => litebox_syscall_rewriter::TargetHost::Linux,
        Some(CliTargetHost::Macos) => litebox_syscall_rewriter::TargetHost::MacOs,
        Some(CliTargetHost::Windows) => litebox_syscall_rewriter::TargetHost::Windows,
        None => {
            litebox_syscall_rewriter::RewriteOptions::for_binary(&input_binary_bytes).target_host()
        }
    };
    let output_binary = litebox_syscall_rewriter::rewrite_binary_with_options(
        &input_binary_bytes,
        cli_args.trampoline_addr,
        litebox_syscall_rewriter::RewriteOptions::new(host, cli_args.virtualize_x18),
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
    fn no_arguments_show_architecture_options() {
        let error = CliArgs::try_parse_from(["litebox_syscall_rewriter"]).unwrap_err();
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        );
        let help = error.to_string();
        assert!(help.contains("--target-host"));
        assert!(help.contains("--virtualize-x18"));
        assert!(help.contains("development/testing"));
    }
}
