// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Restrict this crate to only work on Windows. For now, we are restricting this to only x86-64
// Windows, but we _may_ allow for more in the future, if we find it useful to do so.
#![cfg(all(target_os = "windows", target_arch = "x86_64"))]

extern crate alloc;

use anyhow::{Context as _, Result};
use clap::Parser;
use litebox::platform::{ForkError, ProcessHandle as _, ProcessProvider};
use litebox::process::ProcessError;
use litebox_broker_local_userland as broker;
use litebox_common_linux::program_startup::{LinuxProcessStartup, LinuxProgramStartup};
use litebox_platform_windows_userland::{GuestTlsMode, WindowsUserland};
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;

use litebox_broker_transport_windows_userland::existing_runner::{
    ExistingRunnerDescriptor, unique_control_channel,
};

type Platform = WindowsUserland<{ litebox_common_linux::PAGE_SIZE }>;

struct NativeForkRunner {
    memory: Arc<litebox_shim_linux::MemoryManager<Platform>>,
}

impl NativeForkRunner {
    /// Configures `builder` to start native fork children.
    fn install(
        builder: litebox_shim_linux::LinuxShimBuilder<Platform>,
    ) -> litebox_shim_linux::LinuxShimBuilder<Platform> {
        // SAFETY: `run_child` abandons the copied task, resets platform state,
        // and reconnects to the broker before running the guest in a fresh shim.
        unsafe { builder.with_native_fork_runner(|memory| Self { memory }) }
    }

    /// Rebuilds the runtime in a clone and returns the guest's exit status.
    fn bootstrap_child(&self, control_pipe: &std::ffi::OsStr) -> Result<i32> {
        let platform = Platform::new();
        Platform::set_guest_tls_mode(GuestTlsMode::Linux);
        let (connection, startup) = broker::connect(control_pipe)?;
        let broker::BrokerConnection {
            local,
            notifications,
            process_image,
        } = connection;
        if process_image.is_some() {
            anyhow::bail!("native fork child unexpectedly received a process image");
        }
        let (litebox, process_id, initial_thread) =
            litebox::LiteBox::new_process_with_broker_local(platform, local);
        let process_id =
            i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
        broker::start_notification_receiver(
            notifications,
            litebox.broker_notification_dispatcher(),
            litebox.broker_failure_dispatcher(),
        )?;
        // SAFETY: Sibling guests were paused with memory-manager locks released before the
        // clone. The fresh platform supports the inherited mappings, and the old runtime is
        // abandoned.
        let builder = unsafe {
            litebox_shim_linux::LinuxShimBuilder::new_for_native_fork(
                platform,
                litebox,
                process_id,
                Arc::clone(&self.memory),
            )
        };
        let shim = Self::install(builder).build();
        let startup = startup.context("native fork child has no startup data")?;
        // SAFETY: The startup describes this clone, whose inherited memory manager the fresh shim
        // now owns; this path never returns to the copied parent runtime.
        let program =
            unsafe { shim.restore_fork_from_native_clone(&startup.payload, initial_thread) }
                .context("failed to restore native fork state")?;
        Ok(run_guest(&shim, program))
    }
}

impl litebox_shim_linux::syscalls::process::ForkRunner<Platform> for NativeForkRunner {
    type ControlChannel = std::ffi::OsString;

    fn create_control_channel(&self) -> Result<std::ffi::OsString, ForkError<ProcessError>> {
        Ok(unique_control_channel())
    }
    fn encode_runner_descriptor(
        &self,
        process: &<Platform as ProcessProvider>::ProcessHandle,
        control_pipe: std::ffi::OsString,
    ) -> Result<Vec<u8>, ProcessError> {
        let process_id = process.process_id().map_err(|error| {
            litebox_util_log::error!("failed to identify native fork child: {error}");
            ProcessError::ServiceFailed
        })?;
        ExistingRunnerDescriptor {
            process_handle: process.as_raw_handle() as usize as u64,
            process_id,
            control_channel: control_pipe,
        }
        .encode()
        .map_err(|_| ProcessError::OutOfMemory)
    }

    unsafe fn run_child(&self, control_pipe: std::ffi::OsString) -> ! {
        // TODO: Rewind the stack to where the forking thread first entered the guest, as the Linux
        // runner's native fork child does. The clone runs on a copy of the stack it forked on,
        // under every frame of its parent's runtime, and guest `execve` keeps the runner process,
        // so a long fork chain deepens the stack with each generation until it overflows.
        // SAFETY: RtlCloneUserProcess cloned only this thread, and this path never returns through
        // the copied parent task or its registration guard.
        let status = match unsafe { Platform::prepare_fork_child() }
            .context("failed to prepare native fork child")
            .and_then(|()| self.bootstrap_child(&control_pipe))
        {
            Ok(status) => status,
            Err(error) => {
                litebox_util_log::error!("native fork child bootstrap failed: {error:#}");
                127
            }
        };
        // Skip CRT and DLL teardown of state copied from the multithreaded parent runtime.
        // SAFETY: This is a clone whose copied runtime must not be torn down.
        unsafe { litebox_platform_windows_userland::process::exit_fork_child(status) }
    }
}
/// Run Linux programs with LiteBox on unmodified Windows.
///
/// The program binary and all its dependencies must be available in the
/// broker-owned file system.
#[derive(Parser, Debug)]
pub struct CliArgs {
    /// The program and arguments passed to it (e.g., `/bin/ls --color`).
    ///
    /// The program path refers to a path inside the broker-owned file system.
    /// All binaries must be pre-rewritten with the syscall rewriter. This is
    /// omitted when the broker starts this runner for a forked or exec'd child,
    /// which gets what to run from the broker instead.
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
    /// Broker-supplied Windows named-pipe path for the local control channel.
    #[arg(
        long = "broker-control-channel",
        value_name = "PIPE_NAME",
        hide = true,
        requires = "unstable",
        help_heading = "Unstable Options"
    )]
    pub broker_control_channel: Option<std::ffi::OsString>,
}

/// Run Linux programs with LiteBox on unmodified Windows
///
/// # Panics
///
/// Can panic if any particulars of the environment are not set up as expected. Ideally, would not
/// panic. If it does actually panic, then ping the authors of LiteBox, and likely a better error
/// message could be thrown instead.
pub fn run(cli_args: CliArgs) -> Result<()> {
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    let platform = Platform::new();
    Platform::set_guest_tls_mode(GuestTlsMode::Linux);
    let control_pipe = cli_args
        .broker_control_channel
        .as_deref()
        .context("file operations require --broker-control-channel")?;
    let (connection, startup) = broker::connect(control_pipe)?;
    let broker::BrokerConnection {
        local,
        notifications,
        process_image,
    } = connection;
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let process_id = i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
    broker::start_notification_receiver(
        notifications,
        litebox.broker_notification_dispatcher(),
        litebox.broker_failure_dispatcher(),
    )?;
    let shim_builder =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id);
    let shim_builder = if std::env::var_os("LITEBOX_DISABLE_NATIVE_FORK").is_none() {
        NativeForkRunner::install(shim_builder)
    } else {
        shim_builder
    };

    let shim = shim_builder.build();
    let startup = startup
        .map(|startup| LinuxProcessStartup::decode(&startup.payload))
        .transpose()
        .context("invalid child Linux process startup")?;
    let (task_params, prog_path, argv, envp) = match startup {
        Some(LinuxProcessStartup::Fork(startup)) => {
            // The child continues at its parent's syscall entry point in this runner. Windows
            // shares an executable's relocated image among running instances, so this runner
            // normally loads where its live parent's did; `restore_fork` rejects it otherwise.
            let program = shim
                .restore_fork(*startup, initial_thread, |offset, pages| {
                    process_image.as_ref().map_or(Ok(()), |image| {
                        image
                            .read(offset, pages)
                            .map_err(|_| litebox_common_linux::errno::Errno::EIO)
                    })
                })
                .context("failed to continue the forked process")?;
            drop(process_image);
            run_program(&shim, program)
        }
        Some(LinuxProcessStartup::Program(startup)) => {
            let LinuxProgramStartup {
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
            // The program path is a Unix-style path inside the tar archive.
            let prog_path = cli_args
                .program_and_arguments
                .first()
                .context("program path missing")?
                .clone();
            let argv = cli_args
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
                            k.bytes().chain(*b"=").chain(v.bytes()).collect::<Vec<u8>>(),
                        )
                        .unwrap()
                    }))
                    .collect()
            } else {
                envp
            };
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    uid: 1000,
                    gid: 1000,
                    euid: 1000,
                    egid: 1000,
                    blocked_signals: litebox_common_linux::signal::SigSet::empty(),
                    ignored_signals: litebox_common_linux::signal::SigSet::empty(),
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

    let program = shim
        .load_program(task_params, initial_thread, &prog_path, argv, envp)
        .unwrap();
    run_program(&shim, program)
}

/// Runs the loaded `program` until it exits, then exits this runner.
fn run_program(
    shim: &litebox_shim_linux::LinuxShim<Platform>,
    program: litebox_shim_linux::LoadedProgram<Platform>,
) -> ! {
    std::process::exit(run_guest(shim, program))
}

/// Runs the loaded `program` until it exits and returns the runner's exit status.
fn run_guest(
    shim: &litebox_shim_linux::LinuxShim<Platform>,
    program: litebox_shim_linux::LoadedProgram<Platform>,
) -> i32 {
    // SAFETY: The entry points belong to `shim`, which outlives the guest thread.
    unsafe {
        litebox_platform_windows_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // Report the guest status for the parent to observe. If the report fails,
    // the broker falls back to the runner's host exit status.
    let _ = shim
        .litebox()
        .report_exit_status(program.process.wait_for_exit_status());
    program.process.wait()
}
