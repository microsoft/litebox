// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use litebox_platform_linux_userland::LinuxUserland as Platform;
use litebox_platform_linux_userland::SeccompScope;
use std::path::PathBuf;

use litebox_broker_local_userland as broker;
use litebox_common_linux::program_startup::{
    LinuxForkStartup, LinuxProcessStartup, LinuxProgramStartup,
};
use litebox_common_linux::signal::SigSet;

// Use a stable non-root guest identity instead of mirroring the host user. This keeps shim
// credentials aligned with packaged guest files and avoids truncating high host IDs.
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
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/usr/bin/python3 --version`).
    ///
    /// The program path must be absolute and refer to a file in the broker-owned file system.
    #[arg(trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
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
    run_with_seccomp(cli_args, SeccompScope::AllThreads)
}

/// Like [`run`], but the seccomp filter confines only the calling thread and
/// threads it creates afterward, leaving the broker's threads unconfined.
///
/// # Panics
///
/// See [`run`].
pub fn run_in_broker_process(cli_args: CliArgs) -> Result<i32> {
    run_with_seccomp(cli_args, SeccompScope::CallingThread)
}

fn run_with_seccomp(cli_args: CliArgs, seccomp_scope: SeccompScope) -> Result<i32> {
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

    let control_socket_path = cli_args
        .broker_control_channel
        .as_deref()
        .context("file operations require --broker-control-channel")?;
    let (connection, startup) =
        litebox_platform_linux_userland::with_guest_signals_blocked(|| {
            broker::connect(control_socket_path)
        })?;
    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    let platform = Platform::new();

    let mut broker_positional_io_fds = Vec::new();
    let mut broker_shutdown_fds = Vec::new();
    let broker::BrokerConnection {
        local: broker_local,
        notifications: broker_notifications,
        coordinator: broker_association_coordinator,
        positional_io_fds,
        shutdown_fd,
        process_image,
    } = connection;
    broker_positional_io_fds.extend(positional_io_fds);
    broker_shutdown_fds.push(shutdown_fd);
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, broker_local);
    let process_id = i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
    broker_association_coordinator.install_dispatch(litebox.broker_failure_dispatcher());
    litebox_platform_linux_userland::with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            broker_notifications,
            broker_association_coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })?;
    let shim_builder =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id);

    let shim = shim_builder.build();
    let startup = match startup {
        Some(startup) => Some(
            LinuxProcessStartup::decode(&startup.payload)
                .context("invalid child Linux process startup")?,
        ),
        None => None,
    };
    let (task_params, prog_path, argv, envp) = match startup {
        Some(LinuxProcessStartup::Fork(startup)) => {
            // The process image is loaded before seccomp forbids inspecting it.
            let program = restore_fork(&shim, *startup, initial_thread, process_image)?;
            litebox_platform_linux_userland::LinuxUserland::enable_seccomp_filter(
                &broker_positional_io_fds,
                &broker_shutdown_fds,
                seccomp_scope,
            );
            return Ok(run_program(&shim, program));
        }
        Some(LinuxProcessStartup::Program(startup)) => {
            let LinuxProgramStartup {
                parent_process_id,
                uid,
                euid,
                gid,
                egid,
                blocked_signals,
                ignored_signals,
                umask,
                path,
                cwd,
                argv,
                envp,
                inherited_fds,
            } = startup;
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    ppid: parent_process_id,
                    uid,
                    euid,
                    gid,
                    egid,
                    blocked_signals,
                    ignored_signals,
                    inherited_fds: Some(inherited_fds),
                    cwd: Some(cwd),
                    umask: Some(umask),
                },
                path,
                argv,
                envp,
            )
        }
        None => {
            let prog_path = cli_args
                .program_and_arguments
                .first()
                .context("program path missing")?
                .clone();
            if !prog_path.starts_with('/') {
                anyhow::bail!(
                    "program path must be absolute (e.g., /usr/bin/ls), got: {prog_path}"
                );
            }
            let argv = cli_args
                .program_and_arguments
                .iter()
                .map(|value| std::ffi::CString::new(value.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .context("invalid program argument")?;
            let proxy_url = cli_args.broker_proxy_url;
            let mut environment = cli_args.environment_variables;
            if cli_args.forward_environment_variables {
                environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
            }
            apply_broker_proxy_environment(&mut environment, proxy_url.as_deref());
            let envp = environment
                .iter()
                .map(|value| std::ffi::CString::new(value.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .context("invalid environment variable")?;
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    ppid: 0,
                    uid: u32::from(DEFAULT_GUEST_UID),
                    euid: u32::from(DEFAULT_GUEST_UID),
                    gid: u32::from(DEFAULT_GUEST_GID),
                    egid: u32::from(DEFAULT_GUEST_GID),
                    blocked_signals: SigSet::empty(),
                    ignored_signals: SigSet::empty(),
                    inherited_fds: None,
                    cwd: None,
                    umask: None,
                },
                prog_path,
                argv,
                envp,
            )
        }
    };

    litebox_platform_linux_userland::LinuxUserland::enable_seccomp_filter(
        &broker_positional_io_fds,
        &broker_shutdown_fds,
        seccomp_scope,
    );

    let program = shim.load_program(task_params, initial_thread, &prog_path, argv, envp)?;
    Ok(run_program(&shim, program))
}

/// Runs the loaded `program` until it exits, returning its exit code.
fn run_program(
    shim: &litebox_shim_linux::LinuxShim<Platform>,
    program: litebox_shim_linux::LoadedProgram<Platform>,
) -> i32 {
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

    // The shell exit code cannot tell a signal death from an exit with code
    // 128+signal, so report the guest status for the parent to observe. If the
    // report fails, the broker falls back to the runner's host exit status.
    let _ = shim
        .litebox()
        .report_exit_status(program.process.wait_for_exit_status());
    program.process.wait_for_unix_shell_exit_code()
}

/// Continues the process a parent duplicated by `fork`, whose memory contents are in
/// `process_image`, if any.
fn restore_fork(
    shim: &litebox_shim_linux::LinuxShim<Platform>,
    startup: LinuxForkStartup,
    initial_thread: litebox::thread::Thread,
    process_image: Option<std::os::fd::OwnedFd>,
) -> Result<litebox_shim_linux::LoadedProgram<Platform>> {
    let process_image = process_image
        .map(|image| {
            let image = std::fs::File::from(image);
            let len = image.metadata()?.len();
            std::io::Result::Ok((image, len))
        })
        .transpose()
        .context("failed to inspect the process image")?;
    shim.restore_fork(startup, initial_thread, |offset, pages| {
        let Some((image, image_len)) = &process_image else {
            return Ok(());
        };
        map_process_image(image, *image_len, offset, pages).map_err(|error| {
            error
                .raw_os_error()
                .and_then(|errno| litebox_common_linux::errno::Errno::try_from(errno).ok())
                .unwrap_or(litebox_common_linux::errno::Errno::EIO)
        })
    })
    .context("failed to continue the forked process")
}

/// Maps `image`, which is `image_len` bytes long, privately over the page-aligned whole `pages`
/// from `offset`, so they share the image's memory until written instead of copying it.
///
/// The pages start zero-filled, and those past the image's end stay so, as accessing a mapping
/// there would fault.
fn map_process_image(
    image: &std::fs::File,
    image_len: u64,
    offset: u64,
    pages: &mut [u8],
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let Some(available) = image_len.checked_sub(offset).filter(|&len| len > 0) else {
        return Ok(());
    };
    let len = usize::try_from(available).map_or(pages.len(), |len| len.min(pages.len()));
    let offset = libc::off_t::try_from(offset)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    // SAFETY: `pages` is exclusively borrowed and page-aligned, and the readable and writable
    // private mapping replacing its first `len` bytes keeps them valid, only changing their
    // contents.
    let mapped = unsafe {
        libc::mmap(
            pages.as_mut_ptr().cast(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            image.as_raw_fd(),
            offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
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
    fn child_runner_cli_does_not_require_root_program() {
        let args = CliArgs::try_parse_from([
            "runner",
            "--unstable",
            "--broker-control-channel",
            "/tmp/broker.sock",
        ])
        .unwrap();

        assert_eq!(args.program_and_arguments, [] as [String; 0]);
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
