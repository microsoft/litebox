// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox::fs::{
    Mode, UserInfo,
    in_mem::{InMem, InitialNode},
};
use litebox_platform_macos_userland::MacosUserland as Platform;
use std::ffi::CString;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::sync::Arc;

const DEFAULT_GUEST_UID: u16 = 1000;
const DEFAULT_GUEST_GID: u16 = 1000;

#[derive(Parser, Debug)]
#[command(about = "Run AArch64 Linux PIE programs on an AArch64 macOS host")]
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

/// Load and run a Linux program.
///
/// # Panics
/// Unsupported guest operations may still panic in the Linux shim.
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

    let program = cli_args
        .program_and_arguments
        .first()
        .context("missing program path")?;
    let prog = if cli_args.program_from_tar {
        if !program.starts_with('/') {
            bail!("--program-from-tar requires an absolute guest path");
        }
        PathBuf::from(program)
    } else {
        std::path::absolute(program)?
    };
    let prog_path = prog.to_str().context("program path must be UTF-8")?;

    let (ancestor_modes_and_users, prog_data) = if cli_args.program_from_tar {
        (Vec::new(), None)
    } else {
        let modes = prog
            .ancestors()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path
                    .metadata()
                    .with_context(|| format!("reading metadata for {}", path.display()))?;
                Ok((
                    Mode::from_bits(metadata.mode()).context("unsupported file mode")?,
                    metadata.uid(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let data = std::fs::read(&prog).with_context(|| format!("reading {}", prog.display()))?;
        (modes, Some(data))
    };
    let tar_data = if let Some(tar_file) = &cli_args.initial_files {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            bail!("Expected a .tar file, found {}", tar_file.display());
        }
        std::fs::read(tar_file).with_context(|| format!("reading {}", tar_file.display()))?
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE.to_vec()
    };

    let platform = Platform::new().context("initializing macOS platform")?;
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let task_params = litebox_common_linux::TaskParams {
        pid: 1,
        ppid: 0,
        uid: u32::from(DEFAULT_GUEST_UID),
        euid: u32::from(DEFAULT_GUEST_UID),
        gid: u32::from(DEFAULT_GUEST_GID),
        egid: u32::from(DEFAULT_GUEST_GID),
    };
    let initial_file_system = {
        let owner_of = |parent_host_user: u32, host_user: u32| {
            if parent_host_user == 0 && host_user == 0 {
                UserInfo::ROOT
            } else {
                UserInfo {
                    user: DEFAULT_GUEST_UID,
                    group: DEFAULT_GUEST_GID,
                }
            }
        };
        let mut entries = Vec::new();
        if let Some(prog_data) = prog_data {
            let mut prev_user = 0;
            for (path, &(mode, user)) in prog
                .ancestors()
                .skip(1)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .skip(1)
                .zip(&ancestor_modes_and_users)
            {
                entries.push((
                    path.to_str().context("non-UTF-8 ancestor")?.to_owned(),
                    InitialNode::Directory {
                        mode,
                        owner: owner_of(prev_user, user),
                    },
                ));
                prev_user = user;
            }
            let &(mode, user) = ancestor_modes_and_users
                .last()
                .context("program path has no ancestors")?;
            entries.push((
                prog_path.to_owned(),
                InitialNode::File {
                    mode,
                    owner: owner_of(prev_user, user),
                    data: prog_data.into(),
                },
            ));
        }
        let tmp_mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        if let Some((_, node)) = entries.iter_mut().find(|(path, _)| path == "/tmp") {
            let InitialNode::Directory { mode, .. } = node else {
                unreachable!()
            };
            *mode = tmp_mode;
        } else {
            entries.push((
                "/tmp".to_owned(),
                InitialNode::Directory {
                    mode: tmp_mode,
                    owner: UserInfo::ROOT,
                },
            ));
        }
        shim_builder.default_fs(InMem::new_initialized(entries), tar_data.into())
    };
    let initial_file_system = Arc::new(initial_file_system);
    let shim = shim_builder.build();

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut environment = cli_args.environment_variables;
    if cli_args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
    }
    let envp = environment
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let program = shim
        .load_program(initial_file_system, task_params, prog_path, argv, envp)
        .context("loading Linux ELF (requires a PIE and 16 KiB-compatible LOAD segments)")?;
    // SAFETY: the shim loader supplies valid initial guest code and stack mappings.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    Ok(program.process.wait_for_unix_shell_exit_code())
}
