// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use litebox::fs::Mode;
use litebox_platform_linux_userland::LinuxUserland as Platform;
use memmap2::Mmap;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

mod broker;

extern crate alloc;

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

/// Run Linux programs with LiteBox on unmodified Linux
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
        requires_all = ["unstable", "initial_files"],
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

struct MmappedFile {
    data: &'static [u8],
    abs_path: PathBuf,
}

fn mmapped_file(path: impl AsRef<Path>) -> Result<MmappedFile> {
    let path = path.as_ref();
    let abs_path = std::path::absolute(path)
        .map_err(|e| anyhow!("Could not get absolute path for {}: {}", path.display(), e))?;
    let file = std::fs::File::open(&abs_path)?;
    let data = {
        // SAFETY: We assume that the file given to us is not going to change _externally_ while in
        // the middle of execution. Since we are mapping it as read-only and mapping it only once,
        // we are not planning to change it either. With both these in mind, this call is safe.
        //
        // We need to leak the `Mmap` object, so that it stays alive until the end of the program,
        // rather than being unmapped at function finish (i.e., to get the `'static` lifetime).
        Box::leak(Box::new(unsafe { Mmap::map(&file) }.map_err(|e| {
            anyhow!("Could not read tar file at {}: {}", path.display(), e)
        })?))
    };
    Ok(MmappedFile { data, abs_path })
}

/// Run Linux programs with LiteBox on unmodified Linux
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
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

    let broker_connection = match cli_args.broker_control_channel.as_deref() {
        Some(control_socket_path) => Some(broker::connect(control_socket_path)?),
        None => None,
    };

    let mut cow_eligible_regions: Vec<MmappedFile> = Vec::new();

    // When --program-from-tar is set, the program binary is already in the tar file,
    // so we skip reading it from the host filesystem and skip extracting ancestor modes.
    #[allow(clippy::type_complexity)]
    let (ancestor_modes_and_users, prog_data): (
        Vec<(litebox::fs::Mode, u32)>,
        Option<alloc::borrow::Cow<'static, [u8]>>,
    ) = if cli_args.program_from_tar {
        (Vec::new(), None)
    } else {
        let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
        if !prog.exists() {
            let mut msg = format!("program not found on host filesystem: {}", prog.display());
            if cli_args.initial_files.is_some() {
                msg.push_str(
                    "\nhint: if the program is inside the tar archive, \
                     add --program-from-tar",
                );
            }
            anyhow::bail!(msg);
        }
        let ancestors: Vec<_> = prog.ancestors().collect();
        let modes: Vec<_> = ancestors
            .into_iter()
            .rev()
            .skip(1)
            .map(|path| {
                let metadata = path.metadata().unwrap();
                (
                    litebox::fs::Mode::from_bits(metadata.st_mode()).unwrap(),
                    metadata.st_uid(),
                )
            })
            .collect();
        let file = mmapped_file(&prog)?;
        let data = if cli_args.rewrite_syscalls {
            #[cfg(target_arch = "aarch64")]
            let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf_with_options(
                file.data,
                None,
                litebox_syscall_rewriter::RewriteOptions::new(
                    litebox_syscall_rewriter::TargetHost::Linux,
                    cfg!(feature = "aarch64_virtualize_x18"),
                ),
            )
            .with_context(|| format!("failed to rewrite {}", prog.display()))?;
            #[cfg(not(target_arch = "aarch64"))]
            let rewritten = litebox_syscall_rewriter::hook_syscalls_in_elf(file.data, None)
                .with_context(|| format!("failed to rewrite {}", prog.display()))?;
            rewritten.into()
        } else {
            let data = file.data.into();
            cow_eligible_regions.push(file);
            data
        };
        (modes, Some(data))
    };
    let tar_data: &'static [u8] = if let Some(tar_file) = cli_args.initial_files.as_ref() {
        if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
            anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
        }
        mmapped_file(tar_file)?.data
    } else {
        litebox::fs::tar_ro::EMPTY_TAR_FILE
    };

    // TODO(jb): Clean up platform initialization once we have https://github.com/MSRSSP/litebox/issues/24
    let platform = Platform::new();

    for file in cow_eligible_regions {
        platform.register_cow_region(file.data, file.abs_path);
    }

    let mut broker_positional_io_fds = Vec::new();
    let mut broker_shutdown_fds = Vec::new();
    let shim_builder = if let Some(broker_connection) = broker_connection {
        let broker::BrokerConnection {
            local: broker_local,
            notifications: broker_notifications,
            coordinator: broker_association_coordinator,
            positional_io_fds,
            shutdown_fd,
        } = broker_connection;
        broker_positional_io_fds.extend(positional_io_fds);
        broker_shutdown_fds.push(shutdown_fd);
        let litebox = litebox::LiteBox::new_with_broker_local(platform, broker_local);
        broker_association_coordinator.install_dispatch(litebox.broker_failure_dispatcher());
        broker::start_notification_receiver(
            broker_notifications,
            broker_association_coordinator,
            litebox.broker_notification_dispatcher(),
        )?;
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox)
    } else {
        litebox_shim_linux::LinuxShimBuilder::new(platform)
    };
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
    let initial_file_system = {
        // The in-memory layer is pre-populated at construction, which lets us set up root-owned
        // directories and files without ever acting as root at runtime.
        //
        // A host uid of 0 anywhere along the path means the entry stays root-owned; as soon as a
        // path component belongs to a non-root host user, that component and everything below it
        // is owned by the guest user.
        let owner_of = |parent_host_user: u32, host_user: u32| {
            if parent_host_user == 0 && host_user == 0 {
                litebox::fs::UserInfo::ROOT
            } else {
                litebox::fs::UserInfo {
                    user: DEFAULT_GUEST_UID,
                    group: DEFAULT_GUEST_GID,
                }
            }
        };
        let mut entries: Vec<(String, litebox::fs::in_mem::InitialNode)> = Vec::new();

        // When loading the program from the tar, we don't need to create ancestor
        // directories or write the program binary into the in-memory FS -- the program
        // is already in the tar layer.
        if let Some(prog_data) = prog_data {
            let prog = std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap();
            let ancestors: Vec<_> = prog.ancestors().collect();
            let mut prev_user = 0;
            for (path, &mode_and_user) in ancestors
                .into_iter()
                .skip(1)
                .rev()
                .skip(1)
                .zip(&ancestor_modes_and_users)
            {
                entries.push((
                    path.to_str().unwrap().to_owned(),
                    litebox::fs::in_mem::InitialNode::Directory {
                        mode: mode_and_user.0,
                        owner: owner_of(prev_user, mode_and_user.1),
                    },
                ));
                prev_user = mode_and_user.1;
            }
            let last = ancestor_modes_and_users.last().ok_or_else(|| {
                anyhow!("program path has no ancestor directories (is it the root path?)")
            })?;
            entries.push((
                prog.to_str().unwrap().to_owned(),
                litebox::fs::in_mem::InitialNode::File {
                    mode: last.0,
                    owner: owner_of(prev_user, last.1),
                    data: prog_data,
                },
            ));
        }

        let tmp_mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        if let Some((_, node)) = entries.iter_mut().find(|(path, _)| path == "/tmp") {
            // `/tmp` is an ancestor of the program, so it keeps the owner derived above and only
            // has its mode widened.
            let litebox::fs::in_mem::InitialNode::Directory { mode, .. } = node else {
                unreachable!("ancestors are always directories")
            };
            *mode = tmp_mode;
        } else {
            entries.push((
                "/tmp".to_owned(),
                litebox::fs::in_mem::InitialNode::Directory {
                    mode: tmp_mode,
                    owner: litebox::fs::UserInfo::ROOT,
                },
            ));
        }

        let in_mem = litebox::fs::in_mem::InMem::new_initialized(entries);
        shim_builder.default_fs(in_mem, tar_data.into())
    };

    // We need to get the file path before enabling seccomp.
    // For --program-from-tar the path is already validated as absolute above,
    // so use it directly instead of resolving against the host CWD.
    let prog = if cli_args.program_from_tar {
        PathBuf::from(&cli_args.program_and_arguments[0])
    } else {
        std::path::absolute(Path::new(&cli_args.program_and_arguments[0])).unwrap()
    };
    let prog_path = prog.to_str().ok_or_else(|| {
        anyhow!(
            "Could not convert program path {:?} to a string",
            cli_args.program_and_arguments[0]
        )
    })?;

    let initial_file_system = std::sync::Arc::new(initial_file_system);

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

    let program = shim.load_program(initial_file_system, task_params, prog_path, argv, envp)?;

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

    std::process::exit(program.process.wait())
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
