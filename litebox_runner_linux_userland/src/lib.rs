// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use litebox_platform_linux_userland::LinuxUserland as Platform;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use litebox_broker_local_userland as broker;
use litebox_broker_protocol::fs::{
    FileAccessMode, FileMode as Mode, FileOpenFlags, FileType, FileUser as UserInfo,
};

// Use a stable non-root guest identity instead of mirroring the host user. This keeps shim
// credentials aligned with the in-memory filesystem default user and avoids truncating high host IDs.
const DEFAULT_GUEST_UID: u16 = 1000;
const DEFAULT_GUEST_GID: u16 = 1000;
const MANAGED_PROXY_ENV_KEYS: [&str; 5] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
];

/// Runs a Linux program with LiteBox on unmodified Linux and returns its exit code.
///
/// Detailed logging can be controlled via the `LITEBOX_LOG` environment variable. For example:
/// - `LITEBOX_LOG=debug` to show debug and higher level logs
/// - `LITEBOX_LOG=litebox=debug,litebox::fs=trace` for multiple filters at different levels
#[derive(Parser, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `python3 --version`).
    ///
    /// By default this is a path on the host filesystem. When --program-from-tar
    /// is set, it refers to a path inside the tar archive instead.
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
    /// Pre-fill files into the initial file system state
    // TODO: Might want to extend this to support full directories at some point?
    #[arg(long = "insert-file", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub insert_files: Vec<PathBuf>,
    /// Pre-fill the files in this tar file into the initial file system state
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Apply syscall-rewriter to the ELF file before running it
    ///
    /// This is meant as a convenience feature; real deployments would likely prefer ahead-of-time
    /// rewrite things to amortize costs.
    #[arg(
        long = "rewrite-syscalls",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub rewrite_syscalls: bool,
    /// Load the program binary from the tar file instead of from the host filesystem.
    ///
    /// When set, the program path refers to a path inside the tar filesystem.
    /// The binary must already be rewritten (incompatible with --rewrite-syscalls).
    /// This is used by `litebox-packager` to create fully self-contained tar bundles.
    #[arg(
        long = "program-from-tar",
        requires = "unstable",
        conflicts_with = "rewrite_syscalls",
        help_heading = "Unstable Options"
    )]
    pub program_from_tar: bool,
    /// Broker-supplied Unix socket path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PATH",
        value_hint = clap::ValueHint::FilePath,
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<PathBuf>,
    /// Broker-supplied proxy URL for managed HTTP and HTTPS egress.
    #[arg(
        long = "broker-proxy-url",
        value_name = "URL",
        hide = true,
        requires = "broker_control_channel",
        help_heading = "Unstable Options"
    )]
    pub broker_proxy_url: Option<String>,
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<i32> {
    if cli_args.broker_proxy_url.is_some() && cli_args.broker_control_channel.is_none() {
        return Err(anyhow!(
            "--broker-proxy-url requires --broker-control-channel"
        ));
    }

    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    if !cli_args.insert_files.is_empty() {
        unimplemented!(
            "this should (hopefully soon) have a nicer interface to support loading in files"
        )
    }

    // When loading from tar, the program path is a guest-internal path and must
    // be absolute — LiteBox does not resolve programs via PATH.
    if cli_args.program_from_tar && !cli_args.program_and_arguments[0].starts_with('/') {
        anyhow::bail!(
            "--program-from-tar requires an absolute path (e.g., /usr/bin/ls), \
             got: {}",
            cli_args.program_and_arguments[0]
        );
    }

    let prog = if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).with_context(|| {
            format!(
                "could not resolve program path {}",
                cli_args.program_and_arguments[0]
            )
        })?
    };
    let host_program = (!cli_args.program_from_tar)
        .then(|| prepare_host_program(&cli_args, &prog))
        .transpose()?;

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    let platform = Platform::new();

    let mut broker_positional_io_fds = Vec::new();
    let mut broker_shutdown_fds = Vec::new();
    let control_socket_path = cli_args
        .broker_control_channel
        .as_deref()
        .context("file operations require --broker-control-channel")?;
    let broker::BrokerConnection {
        local: broker_local,
        notifications: broker_notifications,
        coordinator: broker_association_coordinator,
        positional_io_fds,
        shutdown_fd,
    } = litebox_platform_linux_userland::with_guest_signals_blocked(|| {
        broker::connect(control_socket_path)
    })?;
    broker_positional_io_fds.extend(positional_io_fds);
    broker_shutdown_fds.push(shutdown_fd);
    let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
    broker_association_coordinator.install_dispatch(litebox.broker_failure_dispatcher());
    litebox_platform_linux_userland::with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            broker_notifications,
            broker_association_coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })?;
    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox);
    if let Some(host_program) = host_program {
        stage_host_program(shim_builder.litebox(), host_program)?;
    }
    // SAFETY: `gettid` takes no pointer arguments and has no Rust-side aliasing requirements.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) }
        .try_into()
        .context("failed to convert gettid result to i32")?;
    // SAFETY: `getppid` takes no arguments and has no Rust-side aliasing requirements.
    let ppid = unsafe { libc::getppid() };
    let task_params = litebox_common_linux::TaskParams {
        pid: tid,
        ppid,
        uid: u32::from(DEFAULT_GUEST_UID),
        euid: u32::from(DEFAULT_GUEST_UID),
        gid: u32::from(DEFAULT_GUEST_GID),
        egid: u32::from(DEFAULT_GUEST_GID),
    };
    let prog_path = prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert program path {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;

    let shim = shim_builder.build();

    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let proxy_url = cli_args.broker_proxy_url;
    let mut environment = cli_args.environment_variables;
    if cli_args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
    }
    apply_broker_proxy_environment(&mut environment, proxy_url.as_deref());
    let envp = environment
        .iter()
        .map(|value| std::ffi::CString::new(value.as_bytes()).unwrap())
        .collect();

    litebox_platform_linux_userland::LinuxUserland::enable_seccomp_filter(
        &broker_positional_io_fds,
        &broker_shutdown_fds,
    );

    let program = shim.load_program(task_params, prog_path, argv, envp)?;

    #[cfg(feature = "lock_tracing")]
    litebox::sync::start_recording();

    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }

    #[cfg(feature = "lock_tracing")]
    {
        litebox::sync::stop_recording();
        let events = litebox::sync::flush_to_jsonl();
        if !events.is_empty() {
            use std::io::Write;
            if let Ok(mut file) = std::fs::File::create("/tmp/locks.jsonl") {
                for line in &events {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
    }

    Ok(program.process.wait())
}

struct PreparedHostProgram {
    path: String,
    directories: Vec<(String, Mode, UserInfo)>,
    mode: Mode,
    owner: UserInfo,
    data: Vec<u8>,
}

fn prepare_host_program(cli_args: &CliArgs, program: &Path) -> Result<PreparedHostProgram> {
    if !program.exists() {
        let mut message = format!(
            "program not found on host filesystem: {}",
            program.display()
        );
        if cli_args.initial_files.is_some() {
            message.push_str(
                "\nhint: if the program is inside the tar archive, add --program-from-tar",
            );
        }
        anyhow::bail!(message);
    }

    let ancestors: Vec<_> = program.ancestors().skip(1).collect();
    let mut previous_user = 0;
    let mut directories = Vec::new();
    for path in ancestors.into_iter().rev().skip(1) {
        let metadata = path
            .metadata()
            .with_context(|| format!("failed to read metadata for {}", path.display()))?;
        directories.push((
            path_to_string(path)?,
            Mode::from_u32_bits_truncate(metadata.st_mode()),
            guest_owner(previous_user, metadata.st_uid()),
        ));
        previous_user = metadata.st_uid();
    }

    let mut data = std::fs::read(program)
        .with_context(|| format!("failed to read program {}", program.display()))?;
    if cli_args.rewrite_syscalls {
        #[cfg(target_arch = "aarch64")]
        {
            data = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
                &data,
                None,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    cfg!(feature = "aarch64_virtualize_x18"),
                ),
            )
            .with_context(|| format!("failed to rewrite {}", program.display()))?;
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            data = litebox_syscall_rewriter::hook_syscalls_in_elf(&data, None)
                .with_context(|| format!("failed to rewrite {}", program.display()))?;
        }
    }

    let metadata = program
        .metadata()
        .with_context(|| format!("failed to read metadata for {}", program.display()))?;
    Ok(PreparedHostProgram {
        path: path_to_string(program)?,
        directories,
        mode: Mode::from_u32_bits_truncate(metadata.st_mode()),
        owner: guest_owner(previous_user, metadata.st_uid()),
        data,
    })
}

fn stage_host_program(
    litebox: &litebox::LiteBox<Platform>,
    program: PreparedHostProgram,
) -> Result<()> {
    let PreparedHostProgram {
        path,
        directories,
        mode,
        owner,
        data,
    } = program;
    let mut context = litebox::fs::Context::new();
    context.set_acting_user(UserInfo::ROOT);

    // Keep ancestors root-owned and writable until all descendants have been staged. Final
    // metadata is restored from leaf to root so restrictive host modes cannot block setup.
    for (path, mode, _) in &directories {
        let staging_mode = *mode | Mode::RWXU;
        match litebox.mkdir_file(&context, path.as_str(), staging_mode) {
            Ok(()) | Err(litebox::fs::errors::MkdirError::AlreadyExists) => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to stage program directory {path}"));
            }
        }
        let status = litebox
            .path_file_status(&context, path.as_str())
            .with_context(|| format!("failed to inspect program directory {path}"))?;
        if status.file_type != FileType::Directory {
            anyhow::bail!("program path component is not a directory: {path}");
        }
        set_file_metadata(litebox, &context, path, staging_mode, UserInfo::ROOT)?;
    }

    match litebox.unlink_file(&context, path.as_str()) {
        Ok(())
        | Err(litebox::fs::errors::UnlinkError::PathError(
            litebox::fs::errors::PathError::NoSuchFileOrDirectory
            | litebox::fs::errors::PathError::MissingComponent,
        )) => {}
        Err(error) => {
            return Err(error).with_context(|| format!("failed to replace host program {path}"));
        }
    }
    let fd = litebox
        .open_file(
            &context,
            path.as_str(),
            FileAccessMode::WriteOnly,
            FileOpenFlags::CREATE | FileOpenFlags::EXCLUSIVE,
            Mode::RWXU,
        )
        .with_context(|| format!("failed to stage host program {path}"))?;
    let write_result = write_all(litebox, &fd, &path, &data);
    let close_result = litebox
        .close_file(&fd)
        .with_context(|| format!("failed to close staged host program {path}"));
    write_result?;
    close_result?;
    set_file_metadata(litebox, &context, &path, mode, owner)?;

    for (path, mode, owner) in directories.into_iter().rev() {
        set_file_metadata(litebox, &context, &path, mode, owner)?;
    }
    Ok(())
}

fn write_all(
    litebox: &litebox::LiteBox<Platform>,
    fd: &litebox::fs::FileFd,
    path: &str,
    data: &[u8],
) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let written = litebox
            .write_file(fd, &data[offset..], Some(offset))
            .with_context(|| format!("failed to write staged host program {path}"))?;
        if written == 0 {
            anyhow::bail!("failed to write staged host program {path}: write returned zero");
        }
        offset += written;
    }
    Ok(())
}

fn set_file_metadata(
    litebox: &litebox::LiteBox<Platform>,
    context: &litebox::fs::Context,
    path: &str,
    mode: Mode,
    owner: UserInfo,
) -> Result<()> {
    litebox
        .chown_file(context, path, Some(owner.user), Some(owner.group))
        .with_context(|| format!("failed to set owner for staged path {path}"))?;
    litebox
        .chmod_file(context, path, mode)
        .with_context(|| format!("failed to set mode for staged path {path}"))
}

fn guest_owner(previous_user: u32, user: u32) -> UserInfo {
    if previous_user == 0 && user == 0 {
        UserInfo::ROOT
    } else {
        UserInfo {
            user: DEFAULT_GUEST_UID,
            group: DEFAULT_GUEST_GID,
        }
    }
}

fn path_to_string(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("file path is not UTF-8: {}", path.display()))
}

fn apply_broker_proxy_environment(environment: &mut Vec<String>, proxy_url: Option<&str>) {
    environment.retain(|entry| {
        let key = entry
            .split_once('=')
            .map_or(entry.as_str(), |(key, _value)| key);
        proxy_url.is_none()
            || !MANAGED_PROXY_ENV_KEYS
                .iter()
                .any(|managed| managed.eq_ignore_ascii_case(key))
    });

    if let Some(proxy_url) = proxy_url {
        for key in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"] {
            environment.push(format!("{key}={proxy_url}"));
        }
        environment.push("NO_PROXY=".to_owned());
        environment.push("no_proxy=".to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmatic_proxy_url_requires_broker_channel() {
        let mut args = CliArgs::try_parse_from(["runner", "/bin/true"]).unwrap();
        args.broker_proxy_url = Some("http://10.0.2.1:49152".to_owned());

        let error = run(args).unwrap_err();

        assert_eq!(
            error.to_string(),
            "--broker-proxy-url requires --broker-control-channel"
        );
    }

    #[test]
    fn broker_proxy_replaces_proxy_environment() {
        let mut environment = vec![
            "PATH=/bin".to_owned(),
            "HTTPS_PROXY=http://wrong.example:8080".to_owned(),
            "No_Proxy=*".to_owned(),
            "ALL_PROXY=http://wrong.example:8080".to_owned(),
        ];

        apply_broker_proxy_environment(&mut environment, Some("http://10.0.2.1:49152"));

        assert_eq!(
            environment,
            [
                "PATH=/bin",
                "HTTP_PROXY=http://10.0.2.1:49152",
                "http_proxy=http://10.0.2.1:49152",
                "HTTPS_PROXY=http://10.0.2.1:49152",
                "https_proxy=http://10.0.2.1:49152",
                "NO_PROXY=",
                "no_proxy=",
            ]
        );
    }
}
