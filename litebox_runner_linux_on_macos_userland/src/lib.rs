// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Run AArch64 Linux PIE programs on an AArch64 macOS host.
//!
//! `litebox-broker-userland` launches this runner with `--unstable --broker-control-channel`.
//! Without a broker channel, only the development-only `test-broker` feature can run a program,
//! against an in-process broker fixture.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use litebox::platform::{ForkError, ProcessHandle as _, ProcessProvider};
use litebox::process::ProcessError;
use litebox_broker_local_userland as broker;
use litebox_broker_transport_macos_userland::existing_runner::ExistingRunnerDescriptor;
use litebox_common_linux::program_startup::{LinuxProcessStartup, LinuxProgramStartup};
use litebox_common_linux::signal::SigSet;
use litebox_platform_macos_userland::{
    GuestAbi, MacosUserland4K as Platform, set_guest_abi, with_guest_signals_blocked,
};
use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "test-broker")]
mod test_broker;

// Like the Linux runner, use a stable non-root guest identity instead of mirroring the host user.
const DEFAULT_GUEST_UID: u32 = 1000;
const DEFAULT_GUEST_GID: u32 = 1000;

#[derive(Parser, Debug)]
#[command(about = "AArch64 Linux runner for macOS; broker support is required")]
pub struct CliArgs {
    /// Program and its arguments.
    ///
    /// With a broker, the program path must be absolute and refer to a file in the broker-owned
    /// file system. With the in-process test broker, it is a host path unless --program-from-tar
    /// is set.
    #[arg(trailing_var_arg = true, value_hint = clap::ValueHint::CommandWithArguments)]
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
    /// Uncompressed tar containing the Linux interpreter, libraries and files, for the in-process
    /// test broker.
    #[arg(long = "initial-files", value_name = "PATH_TO_TAR", value_hint = clap::ValueHint::FilePath,
          requires = "unstable", conflicts_with = "broker_control_channel", help_heading = "Unstable Options")]
    pub initial_files: Option<PathBuf>,
    /// Resolve the absolute program path within --initial-files.
    #[arg(long = "program-from-tar", requires_all = ["unstable", "initial_files"], help_heading = "Unstable Options")]
    pub program_from_tar: bool,
}

pub fn run(mut cli_args: CliArgs) -> Result<i32> {
    set_guest_abi(GuestAbi::Linux);
    tracing_subscriber::fmt()
        .with_timer(tracing_subscriber::fmt::time::uptime())
        .with_level(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("LITEBOX_LOG")
                .from_env_lossy(),
        )
        .init();

    if let Some(control_socket_path) = cli_args.broker_control_channel.take() {
        return run_with_broker(&control_socket_path, &cli_args);
    }

    #[cfg(not(feature = "test-broker"))]
    {
        let _ = cli_args;
        bail!("the macOS runner requires --broker-control-channel from litebox-broker-userland")
    }

    #[cfg(feature = "test-broker")]
    {
        let requested_program = cli_args
            .program_and_arguments
            .first()
            .context("missing program")?;
        if cli_args.program_from_tar && !requested_program.starts_with('/') {
            bail!("program path in --initial-files must be absolute, got: {requested_program}");
        }
        let platform = Platform::new();
        let host_program =
            (!cli_args.program_from_tar).then(|| std::path::Path::new(requested_program));
        let setup = test_broker::setup(platform, cli_args.initial_files.as_deref(), host_program)?;
        let program_path = if cli_args.program_from_tar {
            requested_program.as_str()
        } else {
            setup.program_path.as_str()
        };
        let (argv, envp) = command_line_strings(&cli_args)?;
        let shim = setup.builder.build();
        let program = shim
            .load_program(
                litebox_common_linux::TaskParams {
                    pid: setup.process_id,
                    uid: 1000,
                    euid: 1000,
                    gid: 1000,
                    egid: 1000,
                    blocked_signals: litebox_common_linux::signal::SigSet::empty(),
                    ignored_signals: litebox_common_linux::signal::SigSet::empty(),
                    inherited_fds: None,
                    cwd: None,
                    umask: None,
                    #[cfg(target_arch = "aarch64")]
                    sve_vl_inherit: false,
                },
                setup.initial_thread,
                program_path,
                argv,
                envp,
            )
            .context("loading Linux program")?;
        // SAFETY: the loader owns valid mappings and has finalized Linux gates;
        // entrypoints retain those mappings until guest execution stops.
        unsafe {
            litebox_platform_macos_userland::run_thread(
                program.entrypoints,
                &mut litebox_common_linux::PtRegs::default(),
            );
        }
        let exit_code = program.process.wait_for_unix_shell_exit_code();
        test_broker::flush_output(&setup.stdio)?;
        Ok(exit_code)
    }
}

/// Starts native fork children, which the broker adopts as runners of their own.
#[derive(Clone)]
struct NativeForkRunner {
    platform: &'static Platform,
    memory: Arc<litebox_shim_linux::MemoryManager<Platform>>,
    /// The `--broker-control-channel` path, which locates the broker's rendezvous with a clone.
    control_socket_path: Arc<Path>,
}

impl NativeForkRunner {
    /// Configures `builder` to start native fork children.
    fn install(
        builder: litebox_shim_linux::LinuxShimBuilder<Platform>,
        platform: &'static Platform,
        control_socket_path: Arc<Path>,
    ) -> litebox_shim_linux::LinuxShimBuilder<Platform> {
        // SAFETY: `run_child` abandons the copied runtime, resets platform state, and builds a
        // fresh runtime on a thread of its own before running the guest in a fresh shim.
        unsafe {
            builder.with_native_fork_runner(|memory| Self {
                platform,
                memory,
                control_socket_path,
            })
        }
    }

    /// Rebuilds the runtime in a clone and returns the guest's shell exit code.
    ///
    /// Runs on a thread created in the clone, with guest signals blocked.
    fn bootstrap_child(&self) -> Result<i32> {
        let (connection, startup) = broker::connect_native_fork_clone(&self.control_socket_path)?;
        let broker::BrokerConnection {
            local,
            notifications,
            coordinator,
        } = connection;
        let (litebox, process_id, initial_thread) =
            litebox::LiteBox::new_process_with_broker_local(self.platform, local);
        let process_id =
            i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
        let guest_finished = Arc::new(AtomicBool::new(false));
        coordinator.install_dispatch(terminate_on_broker_failure(
            &litebox,
            Arc::clone(&guest_finished),
        ));
        broker::start_notification_receiver(
            notifications,
            coordinator,
            litebox.broker_notification_dispatcher(),
        )?;
        // SAFETY: Sibling guests were paused with memory-manager locks released before the
        // clone. The inherited platform owns the inherited mappings, and the old runtime is
        // abandoned.
        let builder = unsafe {
            litebox_shim_linux::LinuxShimBuilder::new_for_native_fork(
                self.platform,
                litebox,
                process_id,
                Arc::clone(&self.memory),
            )
        };
        let shim = Self::install(
            builder,
            self.platform,
            Arc::clone(&self.control_socket_path),
        )
        .build();
        // Dropping the shim closes the association, so a failed restore must not look like a
        // broker failure.
        let _finish_on_return =
            litebox::utils::defer(|| guest_finished.store(true, Ordering::Release));
        let startup = startup.context("native fork child has no startup data")?;
        // SAFETY: The startup describes this clone, whose inherited memory manager the fresh shim
        // now owns; this path never returns to the copied parent runtime.
        let program =
            unsafe { shim.restore_fork_from_native_clone(&startup.payload, initial_thread) }
                .context("failed to restore native fork state")?;
        Ok(run_program(&shim, program, &guest_finished))
    }
}

impl litebox_shim_linux::syscalls::process::ForkRunner<Platform> for NativeForkRunner {
    /// Nothing: the clone finds the broker's rendezvous from its own process ID.
    type ControlChannel = ();

    fn create_control_channel(&self) -> Result<(), ForkError<ProcessError>> {
        Ok(())
    }

    fn encode_runner_descriptor(
        &self,
        process: &<Platform as ProcessProvider>::ProcessHandle,
        (): (),
    ) -> Result<Vec<u8>, ProcessError> {
        let process_id = process.process_id().map_err(|error| {
            litebox_util_log::error!("failed to identify native fork child: {error}");
            ProcessError::ServiceFailed
        })?;
        ExistingRunnerDescriptor { process_id }
            .encode()
            .map_err(|_| ProcessError::OutOfMemory)
    }

    unsafe fn run_child(&self, (): ()) -> ! {
        // The parent runner's runtime (its shim, `LiteBox`, guest tasks, and broker endpoint) and
        // the stacks of its other threads stay in the clone, unreachable, and every later
        // generation of a fork chain inherits them again. Dropping the runtime would touch
        // broker shared memory the clone does not inherit and might wait on threads it lacks.
        // SAFETY: The clone contains only this thread, and this function never returns through
        // the copied guest task or its thread-registration guard.
        let status = match unsafe { Platform::prepare_fork_child() }
            .context("failed to prepare native fork child")
            .and_then(|()| {
                // SAFETY: The clone has a single thread, and nothing uses the closed descriptors.
                unsafe { close_inherited_descriptors() }
                    .context("failed to close inherited descriptors")
            })
            .and_then(|()| {
                // Only guest threads, which unblock them, take guest signals; the runtime thread
                // and its helpers inherit the blocked mask.
                let runner = self.clone();
                with_guest_signals_blocked(|| {
                    // This thread may have parked before the fork, so it must not park again;
                    // see `litebox_platform_macos_userland::process`. Joining does not park, but
                    // `std::thread::scope` would.
                    std::thread::Builder::new()
                        .name("native fork child".into())
                        // A macOS main thread's default, on which every runner first runs its guest.
                        .stack_size(8 << 20)
                        .spawn(move || runner.bootstrap_child())
                        .context("failed to start the native fork child runtime")?
                        .join()
                        .map_err(|_| anyhow::anyhow!("native fork child runtime panicked"))?
                })
            }) {
            Ok(status) => status,
            Err(error) => {
                litebox_util_log::error!("native fork child bootstrap failed: {error:#}");
                127
            }
        };
        // Do not run destructors or atexit handlers copied from the multithreaded parent runtime.
        // SAFETY: `_exit` terminates this process immediately with a conventional shell status.
        unsafe { libc::_exit(status) }
    }
}

/// Returns a broker association failure dispatch that fails pending broker calls and then, unless
/// the guest has finished or the runner is about to return without one (`guest_finished`), ends
/// the runner.
///
/// Without its broker the runner can do nothing useful, but a guest that makes no broker call,
/// such as one spinning or waiting only for signals, would otherwise outlive it. The broker
/// closes the association itself once the runner reports the guest's exit status, so a finished
/// guest's runner is left to exit normally.
fn terminate_on_broker_failure(
    litebox: &litebox::LiteBox<Platform>,
    guest_finished: Arc<AtomicBool>,
) -> impl FnOnce() + Send + 'static {
    let fail_broker_calls = litebox.broker_failure_dispatcher();
    move || {
        fail_broker_calls();
        if !guest_finished.load(Ordering::Acquire) {
            // SAFETY: `_exit` ends the process at once, without running the destructors of the
            // runtime that guest threads may still be using. 69 is `EX_UNAVAILABLE`.
            unsafe { libc::_exit(69) }
        }
    }
}

/// Closes every descriptor above the standard streams that a native fork child inherited, such as
/// the parent's broker control socket, which would otherwise keep the parent's association open.
///
/// # Safety
///
/// No other thread may use or create descriptors concurrently, and nothing may use the closed
/// descriptors afterwards.
unsafe fn close_inherited_descriptors() -> std::io::Result<()> {
    // SAFETY: `getpid` has no preconditions.
    let process_id = unsafe { libc::getpid() };
    // SAFETY: a null buffer requests the buffer size.
    let size = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDLISTFDS,
            0,
            core::ptr::null_mut(),
            0,
        )
    };
    if size <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    let capacity = usize::try_from(size).unwrap() / size_of::<libc::proc_fdinfo>();
    let mut descriptors = Vec::<libc::proc_fdinfo>::with_capacity(capacity);
    // SAFETY: the buffer is writable for `capacity` entries, `size` bytes at most.
    let size = unsafe {
        libc::proc_pidinfo(
            process_id,
            libc::PROC_PIDLISTFDS,
            0,
            descriptors.as_mut_ptr().cast(),
            libc::c_int::try_from(capacity * size_of::<libc::proc_fdinfo>()).unwrap(),
        )
    };
    if size <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `proc_pidinfo` initialized `size` bytes of whole entries.
    unsafe { descriptors.set_len(usize::try_from(size).unwrap() / size_of::<libc::proc_fdinfo>()) };
    for descriptor in descriptors
        .iter()
        .map(|info| info.proc_fd)
        .filter(|&fd| fd > libc::STDERR_FILENO)
    {
        // An error still releases the descriptor on macOS.
        // SAFETY: The caller guarantees that nothing uses the inherited descriptor.
        unsafe { libc::close(descriptor) };
    }
    Ok(())
}

/// Runs the program the broker at `control_socket_path` starts, or the command-line program if
/// the broker supplies none, and returns its shell exit code.
fn run_with_broker(control_socket_path: &Path, cli_args: &CliArgs) -> Result<i32> {
    let (connection, startup) =
        with_guest_signals_blocked(|| broker::connect(control_socket_path))?;
    let platform = Platform::new();
    let broker::BrokerConnection {
        local,
        notifications,
        coordinator,
    } = connection;
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let process_id = i32::try_from(process_id.0).context("process ID does not fit Linux pid_t")?;
    let guest_finished = Arc::new(AtomicBool::new(false));
    coordinator.install_dispatch(terminate_on_broker_failure(
        &litebox,
        Arc::clone(&guest_finished),
    ));
    with_guest_signals_blocked(|| {
        broker::start_notification_receiver(
            notifications,
            coordinator,
            litebox.broker_notification_dispatcher(),
        )
    })?;
    let shim_builder =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id);
    let shim = if std::env::var_os("LITEBOX_DISABLE_NATIVE_FORK").is_none() {
        // The broker observes adopted clones without waiting for them, so let the kernel reap
        // them instead of leaving a zombie per guest fork. Guest signals are virtual, and the
        // clones inherit the disposition for their own clones.
        // SAFETY: Ignoring `SIGCHLD` replaces no handler; this runner has no other host children.
        unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        NativeForkRunner::install(shim_builder, platform, Arc::from(control_socket_path))
    } else {
        shim_builder
    }
    .build();
    // Dropping the shim closes the association, so a failed load must not look like a broker
    // failure.
    let _finish_on_return = litebox::utils::defer(|| guest_finished.store(true, Ordering::Release));
    let startup = startup
        .map(|startup| LinuxProcessStartup::decode(&startup.payload))
        .transpose()
        .context("invalid child Linux process startup")?;
    let (task_params, program_path, argv, envp) = match startup {
        // Only copy-based fork starts a runner with fork startup data, and it is deliberately not
        // implemented on macOS for security reasons; see the broker's `create_image`.
        Some(LinuxProcessStartup::Fork(_)) => {
            bail!("copy-based fork is not supported on macOS")
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
                sve_vl_inherit,
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
                    sve_vl_inherit,
                },
                path,
                argv,
                envp,
            )
        }
        None => {
            let program_path = cli_args
                .program_and_arguments
                .first()
                .context("program path missing")?
                .clone();
            if !program_path.starts_with('/') {
                bail!("program path must be absolute (e.g., /usr/bin/ls), got: {program_path}");
            }
            let (argv, envp) = command_line_strings(cli_args)?;
            (
                litebox_common_linux::TaskParams {
                    pid: process_id,
                    uid: DEFAULT_GUEST_UID,
                    euid: DEFAULT_GUEST_UID,
                    gid: DEFAULT_GUEST_GID,
                    egid: DEFAULT_GUEST_GID,
                    blocked_signals: SigSet::empty(),
                    // Host dispositions use Darwin signal numbers, so none are inherited.
                    ignored_signals: SigSet::empty(),
                    inherited_fds: None,
                    cwd: None,
                    umask: None,
                    sve_vl_inherit: false,
                },
                program_path,
                argv,
                envp,
            )
        }
    };
    let program = shim
        .load_program(task_params, initial_thread, &program_path, argv, envp)
        .context("loading Linux program")?;
    Ok(run_program(&shim, program, &guest_finished))
}

/// Runs a loaded or restored program on the calling thread, waits for all its threads to exit,
/// sets `guest_finished`, reports its exit status to the broker, and returns its shell exit code.
fn run_program(
    shim: &litebox_shim_linux::LinuxShim<Platform>,
    program: litebox_shim_linux::LoadedProgram<Platform>,
    guest_finished: &AtomicBool,
) -> i32 {
    // SAFETY: the loader or fork restore owns valid mappings and has finalized Linux gates;
    // entrypoints retain those mappings until guest execution stops.
    unsafe {
        litebox_platform_macos_userland::run_thread(
            program.entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // The initial thread may exit before its siblings, so the guest finishes only once they all
    // have.
    let exit_status = program.process.wait_for_exit_status();
    guest_finished.store(true, Ordering::Release);
    // The shell exit code cannot tell a signal death from an exit with code 128+signal, so report
    // the guest status for the parent to observe. If the report fails, the broker falls back to
    // the runner's host exit status.
    let _ = shim.litebox().report_exit_status(exit_status);
    program.process.wait_for_unix_shell_exit_code()
}

/// Returns the command-line program arguments and guest environment, including the host
/// environment if forwarded, as C strings.
fn command_line_strings(cli_args: &CliArgs) -> Result<(Vec<CString>, Vec<CString>)> {
    let argv = cli_args
        .program_and_arguments
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in program argument")?;
    let mut environment = cli_args.environment_variables.clone();
    if cli_args.forward_environment_variables {
        environment.extend(std::env::vars().map(|(key, value)| format!("{key}={value}")));
    }
    let envp = environment
        .iter()
        .map(|value| CString::new(value.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("NUL in environment entry")?;
    Ok((argv, envp))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
