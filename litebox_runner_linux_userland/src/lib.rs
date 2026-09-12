// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use litebox_platform_linux_userland::LinuxUserland as Platform;
use std::path::PathBuf;

use litebox_broker_local_userland as broker;

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

    let prog_path = &cli_args.program_and_arguments[0];
    if !prog_path.starts_with('/') {
        anyhow::bail!("program path must be absolute (e.g., /usr/bin/ls), got: {prog_path}");
    }

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

    Ok(program.process.wait_for_unix_shell_exit_code())
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
