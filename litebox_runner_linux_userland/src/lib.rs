// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox::fs::{FileSystem as _, Mode};
use litebox_platform_multiplex::Platform;
use memmap2::Mmap;
use std::os::linux::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

extern crate alloc;

/// Run Linux programs with LiteBox on unmodified Linux
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
    /// Choice of interception backend
    #[arg(
        value_enum,
        long = "interception-backend",
        requires = "unstable",
        help_heading = "Unstable Options",
        default_value = "rewriter"
    )]
    pub interception_backend: InterceptionBackend,
    /// Connect to a TUN device with this name
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        conflicts_with = "network_broker",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Connect to a network broker via IPC (Unix socket) at the given path.
    ///
    /// Mutually exclusive with --tun-device-name. The broker must be listening
    /// on the specified Unix socket path and speaking the litebox IPC network
    /// protocol.
    #[arg(
        long = "network-broker",
        requires = "unstable",
        conflicts_with = "tun_device_name",
        help_heading = "Unstable Options"
    )]
    pub network_broker: Option<String>,
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
    /// Connect to a 9P file broker at the given address (e.g., 10.0.0.1:5640).
    ///
    /// Requires a network backend (--tun-device-name or --network-broker).
    /// The broker must be a 9P2000.L server listening on the network gateway.
    /// All file I/O flows through the shim's network stack, making it
    /// suspension-aware for multi-process support.
    #[arg(
        long = "nine-p-broker",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub nine_p_broker: Option<String>,

    /// Set the initial working directory for the sandboxed process.
    /// Defaults to "/".
    #[arg(long = "cwd", requires = "unstable", help_heading = "Unstable Options")]
    pub working_directory: Option<String>,
}

/// Backends supported for intercepting syscalls
#[non_exhaustive]
#[derive(Debug, Clone, clap::ValueEnum)]
pub enum InterceptionBackend {
    /// Use seccomp-based syscall interception
    Seccomp,
    /// Depend purely on rewriten syscalls to intercept them
    Rewriter,
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
            litebox_syscall_rewriter::hook_syscalls_in_elf(file.data, None)
                .unwrap()
                .into()
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
    //
    // TODO: We also need to pick the type of syscall interception based on whether we want
    // systrap/sigsys interception, or binary rewriting interception. Currently
    // `litebox_platform_linux_userland` does not provide a way to pick between the two.
    let platform = if cli_args.tun_device_name.is_some() {
        Platform::new(cli_args.tun_device_name.as_deref())
    } else if let Some(broker_path) = &cli_args.network_broker {
        use litebox_platform_linux_userland::NetworkTransport;
        let fd = connect_to_broker_ipc(broker_path)?;
        Platform::with_network(Some(NetworkTransport::Ipc(fd)))
    } else {
        Platform::new(None)
    };

    for file in cow_eligible_regions {
        platform.register_cow_region(file.data, file.abs_path);
    }

    litebox_platform_multiplex::set_platform(platform);

    let shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();
    let (in_mem, tar_ro) = build_initial_fs(
        litebox,
        &cli_args,
        &ancestor_modes_and_users,
        prog_data,
        tar_data,
    )?;
    let default_fs = shim_builder.default_fs(in_mem, tar_ro);
    finish_run(shim_builder, default_fs, &cli_args)
}

/// Build the in-memory and tar read-only file systems, including program data and /tmp.
///
/// This is extracted so that both the default and 9P-broker-enabled code paths can share it.
#[allow(clippy::type_complexity)]
fn build_initial_fs(
    litebox: &litebox::LiteBox<Platform>,
    cli_args: &CliArgs,
    ancestor_modes_and_users: &[(litebox::fs::Mode, u32)],
    prog_data: Option<alloc::borrow::Cow<'static, [u8]>>,
    tar_data: &'static [u8],
) -> Result<(
    litebox::fs::in_mem::FileSystem<Platform>,
    litebox::fs::tar_ro::FileSystem<Platform>,
)> {
    let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);

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
            .zip(ancestor_modes_and_users)
        {
            if prev_user == 0 {
                in_mem.with_root_privileges(|fs| {
                    fs.mkdir(path.to_str().unwrap(), mode_and_user.0).unwrap();
                    if mode_and_user.1 != 0 {
                        fs.chown(path.to_str().unwrap(), Some(1000), Some(1000))
                            .unwrap();
                    }
                });
            } else {
                in_mem
                    .mkdir(path.to_str().unwrap(), mode_and_user.0)
                    .unwrap();
            }
            prev_user = mode_and_user.1;
        }

        let open_file =
            |fs: &mut litebox::fs::in_mem::FileSystem<litebox_platform_multiplex::Platform>,
             path,
             mode| {
                let fd = fs
                    .open(
                        path,
                        litebox::fs::OFlags::WRONLY | litebox::fs::OFlags::CREAT,
                        mode,
                    )
                    .unwrap();
                fs.initialize_primarily_read_heavy_file(&fd, prog_data);
                fs.close(&fd).unwrap();
            };
        let last = ancestor_modes_and_users.last().ok_or_else(|| {
            anyhow!("program path has no ancestor directories (is it the root path?)")
        })?;
        if prev_user == 0 {
            in_mem.with_root_privileges(|fs| {
                open_file(fs, prog.to_str().unwrap(), last.0);
                if last.1 != 0 {
                    fs.chown(prog.to_str().unwrap(), Some(1000), Some(1000))
                        .unwrap();
                }
            });
        } else {
            open_file(&mut in_mem, prog.to_str().unwrap(), last.0);
        }
    }
    in_mem.with_root_privileges(|fs| {
        let mode = Mode::RWXU | Mode::RWXG | Mode::RWXO;
        if let Err(err) = fs.mkdir("/tmp", mode) {
            match err {
                litebox::fs::errors::MkdirError::AlreadyExists => {
                    fs.chmod("/tmp", mode).expect("Failed to call chmod");
                }
                _ => panic!(),
            }
        }
    });

    // When using the rewriter backend, the shim's mmap hook handles
    // syscall patching at runtime — no audit library needed.

    let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
    Ok((in_mem, tar_ro))
}

/// Complete the run after the file system has been composed and the shim builder is ready.
///
/// This is generic over the file system type so it can handle both the default and
/// broker-enabled FS compositions.
fn finish_run<FS: litebox_shim_linux::ShimFS>(
    mut shim_builder: litebox_shim_linux::LinuxShimBuilder,
    fs: FS,
    cli_args: &CliArgs,
) -> Result<()> {
    let platform = litebox_platform_multiplex::platform();

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

    shim_builder.set_load_filter(fixup_env);

    match cli_args.interception_backend {
        InterceptionBackend::Seccomp => platform.enable_seccomp_based_syscall_interception(),
        InterceptionBackend::Rewriter => {}
    }

    let argv = build_argv(cli_args);
    let envp = build_envp(cli_args);

    // If a 9P broker is requested, validate that a network backend is configured.
    if cli_args.nine_p_broker.is_some()
        && cli_args.tun_device_name.is_none()
        && cli_args.network_broker.is_none()
    {
        anyhow::bail!(
            "--nine-p-broker requires a network backend (--tun-device-name or --network-broker)"
        );
    }

    // If a 9P broker is requested, build shim → start network → connect 9P → layer FS.
    // The FS type differs between branches, so each must build its own shim and run.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(shim_builder, fs, cli_args, platform, prog_path, argv, envp)
    } else {
        let initial_file_system = std::sync::Arc::new(fs);
        let shim = shim_builder.build();

        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let program = shim.load_program(
            initial_file_system,
            platform.init_task(),
            prog_path,
            argv,
            envp,
            cli_args.working_directory.clone(),
        )?;

        run_program(program, shutdown, net_worker);
    }
}

/// Finish running with a 9P broker providing the lower file system layer.
///
/// Builds the shim, starts the network worker, connects to the 9P broker,
/// layers the resulting FS on top of the base FS, and runs the program.
fn finish_run_with_nine_p<FS: litebox_shim_linux::ShimFS>(
    shim_builder: litebox_shim_linux::LinuxShimBuilder,
    base_fs: FS,
    cli_args: &CliArgs,
    platform: &litebox_platform_multiplex::Platform,
    prog_path: &str,
    argv: Vec<alloc::ffi::CString>,
    envp: Vec<alloc::ffi::CString>,
) -> Result<()> {
    let broker_addr = cli_args.nine_p_broker.as_deref().unwrap();

    // In IPC mode, open a dedicated 9P channel that bypasses smoltcp entirely.
    if let Some(broker_path) = &cli_args.network_broker {
        let channel_fd = connect_nine_p_channel(broker_path)?;
        platform.set_raw_message_fd(channel_fd);

        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let net_worker = start_network_worker(&shim, &shutdown);

        let transport = shim.message_channel();
        let litebox = shim.litebox();
        let nine_p_fs =
            litebox::fs::nine_p::FileSystem::new(litebox, transport, 65536, "root", "/")
                .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

        let combined = litebox::fs::layered::FileSystem::new(
            litebox,
            base_fs,
            nine_p_fs,
            litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
        );
        let combined_fs = std::sync::Arc::new(combined);

        let program = shim.load_program(
            combined_fs,
            platform.init_task(),
            prog_path,
            argv,
            envp,
            cli_args.working_directory.clone(),
        )?;

        run_program(program, shutdown, net_worker);
    }

    // TUN mode: connect via TCP through the guest's smoltcp network stack.
    let addr: core::net::SocketAddr = broker_addr
        .parse()
        .map_err(|e| anyhow!("Invalid 9P broker address '{broker_addr}': {e}"))?;

    let shim = shim_builder.build();
    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = start_network_worker(&shim, &shutdown);

    if cfg!(debug_assertions) {
        eprintln!("Connecting to 9P broker at {broker_addr}...");
    }

    let transport = {
        let mut attempts = 0;
        loop {
            match shim.tcp_connection(addr) {
                Ok(t) => break t,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to 9P broker at {broker_addr} after {attempts} attempts: {e:?}"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    };

    let litebox = shim.litebox();
    let nine_p_fs = litebox::fs::nine_p::FileSystem::new(litebox, transport, 65536, "root", "/")
        .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

    if cfg!(debug_assertions) {
        eprintln!("9P broker connected.");
    }

    let combined = litebox::fs::layered::FileSystem::new(
        litebox,
        base_fs,
        nine_p_fs,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    let combined_fs = std::sync::Arc::new(combined);

    let program = shim.load_program(
        combined_fs,
        platform.init_task(),
        prog_path,
        argv,
        envp,
        cli_args.working_directory.clone(),
    )?;

    run_program(program, shutdown, net_worker);
}

/// Run the loaded program and exit with its return code.
///
/// This function never returns — it calls `std::process::exit()`.
fn run_program<FS: litebox_shim_linux::ShimFS>(
    program: litebox_shim_linux::LoadedProgram<FS>,
    shutdown: std::sync::Arc<core::sync::atomic::AtomicBool>,
    net_worker: Option<std::thread::JoinHandle<()>>,
) -> ! {
    #[cfg(feature = "lock_tracing")]
    litebox::sync::start_recording();

    unsafe {
        litebox_platform_linux_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::ExecutionContext::default(),
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

    if let Some(net_worker) = net_worker {
        shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
        net_worker.join().unwrap();
    }
    std::process::exit(program.process.wait())
}

/// Connect to a network broker via Unix domain socket.
fn connect_to_broker_ipc(path: &str) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        anyhow::bail!("Failed to create Unix socket for broker IPC");
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    let path_bytes = path.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        anyhow::bail!("Broker IPC socket path too long: {path}");
    }
    for (i, &b) in path_bytes.iter().enumerate() {
        #[allow(clippy::cast_possible_wrap)]
        {
            addr.sun_path[i] = b as libc::c_char;
        }
    }

    let ret = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
            },
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        // EINPROGRESS is expected for non-blocking connect.
        if errno != libc::EINPROGRESS {
            anyhow::bail!("Failed to connect to broker IPC at {path}: errno {errno}");
        }
        // Wait for connection to complete (with 5s timeout).
        let mut pfd = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&fd),
            events: libc::POLLOUT,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&raw mut pfd, 1, 5000) };
        if ret <= 0 {
            anyhow::bail!("Timed out connecting to broker IPC at {path}");
        }
        // Check for connect error.
        let mut err: libc::c_int = 0;
        #[allow(clippy::cast_possible_truncation)]
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&fd),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&raw mut err).cast::<libc::c_void>(),
                &raw mut len,
            );
        }
        if err != 0 {
            anyhow::bail!("Failed to connect to broker IPC at {path}: errno {err}");
        }
    }

    // Perform IPC handshake: send magic + version + MTU, receive response.
    perform_ipc_handshake(&fd)?;

    Ok(fd)
}

/// Open a dedicated 9P channel to the broker via Unix domain socket.
///
/// This is a **blocking** socket — 9P is strictly request-response, so the
/// transport blocks waiting for each reply.  The broker identifies this
/// connection by the `LB9P` handshake magic and routes it directly to the
/// 9P server (bypassing smoltcp).
fn connect_nine_p_channel(broker_path: &str) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // Blocking socket (no SOCK_NONBLOCK).
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        anyhow::bail!("Failed to create Unix socket for 9P channel");
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    #[allow(clippy::cast_possible_truncation)]
    {
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    }
    let path_bytes = broker_path.as_bytes();
    if path_bytes.len() >= addr.sun_path.len() {
        anyhow::bail!("Broker socket path too long: {broker_path}");
    }
    for (i, &b) in path_bytes.iter().enumerate() {
        #[allow(clippy::cast_possible_wrap)]
        {
            addr.sun_path[i] = b as libc::c_char;
        }
    }

    let ret = unsafe {
        libc::connect(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            (&raw const addr).cast::<libc::sockaddr>(),
            #[allow(clippy::cast_possible_truncation)]
            {
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
            },
        )
    };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        anyhow::bail!("Failed to connect 9P channel to broker at {broker_path}: errno {errno}");
    }

    // Send 9P channel handshake: "LB9P" magic (4 bytes).
    let magic = b"LB9P";
    let ret = unsafe {
        libc::send(
            std::os::fd::AsRawFd::as_raw_fd(&fd),
            magic.as_ptr().cast::<libc::c_void>(),
            4,
            libc::MSG_NOSIGNAL,
        )
    };
    if ret != 4 {
        anyhow::bail!("Failed to send 9P channel handshake");
    }

    Ok(fd)
}

/// IPC handshake constants.
const HANDSHAKE_MAGIC: &[u8; 4] = b"LBNP";
const HANDSHAKE_VERSION: u16 = 1;
const HANDSHAKE_MTU: u16 = 1600;

/// Send and receive the IPC handshake on the runner side.
fn perform_ipc_handshake(fd: &std::os::fd::OwnedFd) -> Result<()> {
    use std::os::fd::AsRawFd;

    // Build handshake message: magic (4) + version (2) + MTU (2) = 8 bytes.
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(HANDSHAKE_MAGIC);
    msg[4..6].copy_from_slice(&HANDSHAKE_VERSION.to_le_bytes());
    msg[6..8].copy_from_slice(&HANDSHAKE_MTU.to_le_bytes());

    // Send handshake (retry on EAGAIN for non-blocking sockets).
    let mut sent = 0usize;
    while sent < 8 {
        let ret = unsafe {
            libc::send(
                fd.as_raw_fd(),
                msg[sent..].as_ptr().cast::<libc::c_void>(),
                8 - sent,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                #[allow(clippy::cast_sign_loss)]
                {
                    sent += ret as usize;
                }
            }
            std::cmp::Ordering::Equal => {
                anyhow::bail!("IPC handshake send: peer closed");
            }
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    let mut wpfd = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&raw mut wpfd, 1, 100);
                    }
                    continue;
                }
                anyhow::bail!("IPC handshake send failed: errno {errno}");
            }
        }
    }

    // Wait for response with 10s timeout.
    let mut pfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&raw mut pfd, 1, 10_000) };
    if ret <= 0 {
        anyhow::bail!("IPC handshake response timeout");
    }

    // Read response (retry on EAGAIN).
    let mut resp = [0u8; 8];
    let mut read = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while read < 8 {
        let ret = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                resp[read..].as_mut_ptr().cast::<libc::c_void>(),
                8 - read,
                libc::MSG_DONTWAIT,
            )
        };
        match ret.cmp(&0) {
            std::cmp::Ordering::Greater => {
                #[allow(clippy::cast_sign_loss)]
                {
                    read += ret as usize;
                }
            }
            std::cmp::Ordering::Equal => {
                anyhow::bail!("IPC handshake response: peer closed");
            }
            std::cmp::Ordering::Less => {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    if std::time::Instant::now() > deadline {
                        anyhow::bail!("IPC handshake response read timeout");
                    }
                    let mut rpfd = libc::pollfd {
                        fd: fd.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&raw mut rpfd, 1, 100);
                    }
                    continue;
                }
                anyhow::bail!("IPC handshake response read failed: errno {errno}");
            }
        }
    }

    // Validate response.
    if &resp[0..4] != HANDSHAKE_MAGIC {
        anyhow::bail!("IPC handshake: bad magic in response");
    }
    let version = u16::from_le_bytes([resp[4], resp[5]]);
    if version != HANDSHAKE_VERSION {
        anyhow::bail!(
            "IPC handshake: version mismatch (got {version}, expected {HANDSHAKE_VERSION})"
        );
    }
    let mtu = u16::from_le_bytes([resp[6], resp[7]]);
    if mtu != HANDSHAKE_MTU {
        anyhow::bail!("IPC handshake: MTU mismatch (broker sent {mtu}, we expect {HANDSHAKE_MTU})");
    }
    #[cfg(debug_assertions)]
    eprintln!("IPC handshake complete: broker MTU={mtu}");

    Ok(())
}

/// Pin the current thread to a specific CPU core
fn pin_thread_to_cpu(cpu: usize) {
    unsafe {
        let mut set = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(cpu, &mut set);

        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &raw const set) != 0 {
            eprintln!("Warning: Failed to pin thread to CPU core {cpu}");
        }
    }
}

/// Start the network worker thread if any network backend is configured.
fn start_network_worker<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    shutdown: &std::sync::Arc<core::sync::atomic::AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    if !litebox_platform_multiplex::platform().has_network() {
        return None;
    }
    let shim = shim.clone();
    let shutdown_clone = shutdown.clone();
    let child = litebox_platform_linux_userland::spawn_host_thread(move || {
        const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_micros(100);
        pin_thread_to_cpu(0);

        while !shutdown_clone.load(core::sync::atomic::Ordering::Relaxed) {
            let timeout = loop {
                match shim.perform_network_interaction() {
                    litebox::net::PlatformInteractionReinvocationAdvice::CallAgainImmediately => {}
                    litebox::net::PlatformInteractionReinvocationAdvice::WaitOnDeviceOrSocketInteraction { timeout } => {
                        break timeout;
                    }
                }
            };
            let wait = match timeout {
                Some(t) if t < DEFAULT_TIMEOUT => t,
                _ => DEFAULT_TIMEOUT,
            };
            litebox_platform_multiplex::platform().wait_on_network(Some(wait));
        }
        while shim.perform_network_interaction().call_again_immediately() {}
    });
    Some(child)
}

/// Build argv from CLI args.
fn build_argv(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect()
}

/// Build envp from CLI args, optionally forwarding host environment.
fn build_envp(cli_args: &CliArgs) -> Vec<std::ffi::CString> {
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    if cli_args.forward_environment_variables {
        envp.into_iter()
            .chain(std::env::vars().map(|(k, v)| {
                std::ffi::CString::new(
                    k.bytes()
                        .chain([b'='])
                        .chain(v.bytes())
                        .collect::<Vec<u8>>(),
                )
                .unwrap()
            }))
            .collect()
    } else {
        envp
    }
}

fn fixup_env(_envp: &mut Vec<alloc::ffi::CString>) {
    // No environment fixups needed — the shim's mmap hook handles
    // syscall patching at runtime without LD_AUDIT.
}
