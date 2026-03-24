// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Result, anyhow};
use clap::Parser;
use litebox_platform_multiplex::Platform;
use std::path::PathBuf;

/// Run Linux programs with LiteBox on unmodified Windows.
///
/// The program binary and all its dependencies (including `litebox_rtld_audit.so`)
/// must be provided inside a tar archive via `--initial-files`. The program path
/// refers to a path inside the tar archive.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the tar archive provided via
    /// `--initial-files`. All binaries must be pre-rewritten with the syscall
    /// rewriter and the tar must include `litebox_rtld_audit.so`.
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
    /// Tar archive containing the program, its shared libraries, and litebox_rtld_audit.so.
    ///
    /// All ELF binaries should be pre-rewritten with the syscall rewriter
    /// (e.g., via `litebox-packager`).
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath)]
    pub initial_files: PathBuf,
    /// Connect to a TUN device with this name (e.g., "litebox0").
    ///
    /// Requires `wintun.dll` next to the runner executable (or on the PATH).
    /// The adapter will be created if it doesn't already exist.
    #[arg(
        long = "tun-device-name",
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub tun_device_name: Option<String>,
    /// Connect to a 9P file broker at the given address (e.g., 10.0.0.1:5640).
    ///
    /// Requires --tun-device-name. The broker must be a 9P2000.L server
    /// listening on the TUN gateway.
    #[arg(
        long = "nine-p-broker",
        requires_all = ["unstable", "tun_device_name"],
        help_heading = "Unstable Options"
    )]
    pub nine_p_broker: Option<String>,
    /// Set the initial working directory for the sandboxed process.
    /// Defaults to "/".
    #[arg(long = "cwd", requires = "unstable", help_heading = "Unstable Options")]
    pub working_directory: Option<String>,
}

/// Run Linux programs with LiteBox on unmodified Windows
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    let tar_file = &cli_args.initial_files;
    if tar_file.extension().and_then(|x| x.to_str()) != Some("tar") {
        anyhow::bail!("Expected a .tar file, found {}", tar_file.display());
    }
    let tar_data = std::fs::read(tar_file)
        .map_err(|e| anyhow!("Could not read tar file at {}: {}", tar_file.display(), e))?;

    let platform = Platform::new(cli_args.tun_device_name.as_deref());
    litebox_platform_multiplex::set_platform(platform);
    let mut shim_builder = litebox_shim_linux::LinuxShimBuilder::new();
    let litebox = shim_builder.litebox();

    // The program path is a Unix-style path inside the tar archive.
    let prog_path = &cli_args.program_and_arguments[0];

    let initial_file_system = {
        let mut in_mem = litebox::fs::in_mem::FileSystem::new(litebox);
        in_mem.with_root_privileges(|fs| {
            use litebox::fs::FileSystem as _;
            fs.mkdir(
                "/tmp",
                litebox::fs::Mode::RWXU | litebox::fs::Mode::RWXG | litebox::fs::Mode::RWXO,
            )
            .unwrap();
            fs.chown("/tmp", Some(1000), Some(1000)).unwrap();
        });

        let tar_ro = litebox::fs::tar_ro::FileSystem::new(litebox, tar_data.into());
        shim_builder.default_fs(in_mem, tar_ro)
    };

    shim_builder.set_load_filter(fixup_env);

    let argv: Vec<_> = cli_args
        .program_and_arguments
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp: Vec<_> = cli_args
        .environment_variables
        .iter()
        .map(|x| std::ffi::CString::new(x.bytes().collect::<Vec<u8>>()).unwrap())
        .collect();
    let envp = if cli_args.forward_environment_variables {
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
    };

    // If a 9P broker is requested, build shim → start network → connect 9P → layer FS.
    if cli_args.nine_p_broker.is_some() {
        finish_run_with_nine_p(
            shim_builder,
            initial_file_system,
            &cli_args,
            platform,
            prog_path,
            argv,
            envp,
        )
    } else {
        let initial_file_system = std::sync::Arc::new(initial_file_system);
        let shim = shim_builder.build();
        let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
        let network_thread = start_network_worker(&shim, &shutdown, &cli_args);

        let cwd = cli_args.working_directory.clone();
        let program = shim
            .load_program(
                initial_file_system,
                platform.init_task(),
                prog_path,
                argv,
                envp,
                cwd,
            )
            .unwrap();

        run_program(program, shutdown, network_thread)
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
    let addr: core::net::SocketAddr = broker_addr
        .parse()
        .map_err(|e| anyhow!("Invalid 9P broker address '{broker_addr}': {e}"))?;

    let shim = shim_builder.build();

    let shutdown = std::sync::Arc::new(core::sync::atomic::AtomicBool::new(false));
    let net_worker = start_network_worker(&shim, &shutdown, cli_args);

    if cfg!(debug_assertions) {
        eprintln!("Connecting to 9P broker at {broker_addr}...");
    }

    // Retry connection with backoff (broker might not be listening yet).
    let transport = {
        let mut attempts = 0;
        loop {
            match shim.tcp_connection(addr) {
                Ok(t) => break t,
                Err(e) => {
                    attempts += 1;
                    if attempts >= 50 {
                        return Err(anyhow!(
                            "Failed to connect to 9P broker at {broker_addr} \
                             after {attempts} attempts: {e:?}"
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    };

    let litebox = shim.litebox();
    let (writer, reader) = transport.split();
    let msize = 4 * 1024 * 1024u32;
    let (nine_p_fs, mut reader) =
        litebox::fs::nine_p::FileSystem::new(litebox, writer, reader, msize, "root", "/")
            .map_err(|e| anyhow!("9P attach failed: {e:?}"))?;

    if cfg!(debug_assertions) {
        eprintln!("9P broker connected.");
    }

    let worker_handle = nine_p_fs.worker_handle();
    let _nine_p_worker = std::thread::spawn(move || {
        let mut buf = alloc::vec::Vec::with_capacity(msize as usize);
        while worker_handle.poll_responses(&mut reader, &mut buf) {}
    });

    let combined = litebox::fs::layered::FileSystem::new(
        litebox,
        base_fs,
        nine_p_fs,
        litebox::fs::layered::LayeringSemantics::LowerLayerWritableFiles,
    );
    let combined_fs = std::sync::Arc::new(combined);

    let cwd = cli_args.working_directory.clone();
    let program = shim
        .load_program(
            combined_fs,
            platform.init_task(),
            prog_path,
            argv,
            envp,
            cwd,
        )
        .unwrap();

    run_program(program, shutdown, net_worker)
}

/// Run the loaded program and exit with its return code.
fn run_program<FS: litebox_shim_linux::ShimFS>(
    program: litebox_shim_linux::LoadedProgram<FS>,
    shutdown: std::sync::Arc<core::sync::atomic::AtomicBool>,
    net_worker: Option<std::thread::JoinHandle<()>>,
) -> ! {
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::ExecutionContext::default(),
        );
    }
    let exit_code = program.process.wait();

    // Signal network worker to stop and wait for it.
    shutdown.store(true, core::sync::atomic::Ordering::Relaxed);
    if let Some(handle) = net_worker {
        let _ = handle.join();
    }

    std::process::exit(exit_code)
}

/// Start the network worker thread if a TUN device is configured.
fn start_network_worker<FS: litebox_shim_linux::ShimFS>(
    shim: &litebox_shim_linux::LinuxShim<FS>,
    shutdown: &std::sync::Arc<core::sync::atomic::AtomicBool>,
    cli_args: &CliArgs,
) -> Option<std::thread::JoinHandle<()>> {
    cli_args.tun_device_name.as_ref()?;
    let shim = shim.clone();
    let shutdown_clone = shutdown.clone();
    let child = std::thread::Builder::new()
        .name("network-worker".into())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            const DEFAULT_TIMEOUT: core::time::Duration = core::time::Duration::from_micros(100);

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
                litebox_platform_multiplex::platform().wait_on_tun(Some(wait));
            }
            // Drain remaining network interactions before exiting.
            while shim.perform_network_interaction().call_again_immediately() {}
        })
        .expect("failed to spawn network worker thread");
    Some(child)
}

fn fixup_env(envp: &mut Vec<alloc::ffi::CString>) {
    // Always inject LD_AUDIT so the dynamic linker loads the audit library
    // that sets up trampolines for rewritten binaries.
    let p = c"LD_AUDIT=/lib/litebox_rtld_audit.so";
    let has_ld_audit = envp.iter().any(|var| var.as_c_str() == p);
    if !has_ld_audit {
        envp.push(p.into());
    }
}
