// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run compatible AArch64 Linux PIE programs on Apple Silicon.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox::fs::{
    Mode, UserInfo,
    in_mem::{InMem, InitialNode},
};
use litebox_platform_macos_userland::MacosUserland;
use std::{ffi::CString, path::PathBuf, sync::Arc};

#[derive(Debug, Parser)]
#[command(about = "Run AArch64 Linux PIE programs on macOS (experimental, native 16 KiB pages)")]
pub struct CliArgs {
    /// Program and its arguments; host path unless --program-from-tar is set.
    #[arg(required = true, trailing_var_arg = true)]
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
    #[arg(long = "initial-files", requires = "unstable")]
    pub initial_files: Option<PathBuf>,
    /// Resolve the absolute program path within --initial-files.
    #[arg(long = "program-from-tar", requires_all = ["unstable", "initial_files"])]
    pub program_from_tar: bool,
}

/// Load and run a Linux program.
///
/// # Panics
/// Unsupported guest operations may still panic in the Linux shim.
pub fn run(args: CliArgs) -> Result<i32> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .try_init();
    let program = args
        .program_and_arguments
        .first()
        .context("missing program path")?;
    let path = if args.program_from_tar {
        if !program.starts_with('/') {
            bail!("--program-from-tar requires an absolute guest path");
        }
        PathBuf::from(program)
    } else {
        std::path::absolute(program)?
    };
    let guest_path = path.to_str().context("program path must be UTF-8")?;
    let mut entries = Vec::new();
    let owner = UserInfo {
        user: 1000,
        group: 1000,
    };
    let directory_mode = Mode::RWXU | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH;
    if !args.program_from_tar {
        let data = std::fs::read(&path).with_context(|| {
            format!(
                "reading {} (use --program-from-tar for paths inside the archive)",
                path.display()
            )
        })?;
        for ancestor in path
            .ancestors()
            .skip(1)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .skip(1)
        {
            entries.push((
                ancestor.to_str().context("non-UTF-8 ancestor")?.to_owned(),
                InitialNode::Directory {
                    mode: directory_mode,
                    owner,
                },
            ));
        }
        entries.push((
            guest_path.to_owned(),
            InitialNode::File {
                mode: directory_mode,
                owner,
                data: data.into(),
            },
        ));
    }
    if !entries.iter().any(|(p, _)| p == "/tmp") {
        entries.push((
            "/tmp".to_owned(),
            InitialNode::Directory {
                mode: Mode::RWXU | Mode::RWXG | Mode::RWXO,
                owner: UserInfo::ROOT,
            },
        ));
    }
    let tar_data = if let Some(tar) = args.initial_files {
        std::fs::read(&tar).with_context(|| format!("reading {}", tar.display()))?
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE.to_vec()
    };
    let guest_argv = args
        .program_and_arguments
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut environment = args.environment_variables;
    if args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(k, v)| format!("{k}={v}")));
    }
    let envp = environment
        .iter()
        .map(|s| CString::new(s.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    let platform = MacosUserland::new().context("initializing macOS platform")?;
    let builder = litebox_shim_linux::LinuxShimBuilder::new(platform);
    let fs = Arc::new(builder.default_fs(InMem::new_initialized(entries), tar_data.into()));
    let shim = builder.build();
    let task = litebox_common_linux::TaskParams {
        pid: 1,
        ppid: 0,
        uid: 1000,
        euid: 1000,
        gid: 1000,
        egid: 1000,
    };
    let program = shim
        .load_program(fs, task, guest_path, guest_argv, envp)
        .context("loading Linux ELF (requires a PIE and 16 KiB-compatible LOAD segments)")?;
    // SAFETY: the shim loader supplies the initial guest code and stack mappings.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    let status = program.process.wait();
    // Convert the shim's 256 + signo to shell status 128 + signo.
    Ok(if status >= 256 {
        128 + status - 256
    } else {
        status
    })
}
