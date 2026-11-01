// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the one Linux program the kernel asks for, in the message format of
//! [`litebox_common_vm_abi::program`], and replies with its exit status.
//! The program's files, including standard streams, are the broker's.
//!
//! In a launched process (see `litebox_common_vm_abi`, Messages), runs
//! instead the program its startup data names, with the descriptors,
//! credentials, and directory it inherits, and exits; its parent learns its
//! exit status from the broker.
//!
//! `fork`: the shim's native fork ([`VmForkRunner`]) clones the runner
//! process (see `litebox_common_vm_abi`, `CloneKind::Process`, and
//! `litebox_platform_vm_userland::process`): a copy-on-write copy, the
//! program's memory included, which becomes the child once the kernel adopts
//! it. The clone's runner leaves the parent's at once: it goes on on the main
//! stack, with a broker association and a shim of its own over the program's
//! memory, and never uses or frees anything else of the parent's runner (e.g.,
//! its shim, broker endpoint, and notification receiver). Its lockdown is its
//! parent's, so it neither makes `Ready` nor restricts its calls; its
//! handshake call, allowed regardless, returns the response of the handshake
//! that the kernel made as it adopted the clone.
//!
//! Lockdown: after the broker connects, no new association; once serving,
//! only [`SERVING_CALLS`] ([`LAUNCHED_CALLS`] in a launched process, after
//! `Ready`). Executable memory stays allowed, as a Linux program may map code
//! (W^X still holds).
//!
//! Time: monotonic clocks are the kernel clock; the wall clock (`time`,
//! `gettimeofday`, `CLOCK_REALTIME`) is the kernel's, read from kvm-clock at
//! boot and advanced by the kernel clock, or, without kvm-clock (e.g., under
//! QEMU's TCG), starting at the Unix epoch. `alarm` and `setitimer` raise
//! `SIGALRM` from platform timers; timer files are broker timers.
//!
//! Threads: each of the program's threads is a runner thread (see
//! `litebox_platform_vm_userland::thread`), which the kernel schedules.
//!
//! Waits block in the kernel (its futex) until a wake, their timeout, a
//! platform timer, or a broker notification (e.g., a timer file's expiry,
//! or standard input arriving), which the broker's notification receiver
//! dispatches. The kernel also interrupts the running program once it
//! publishes one, so a nonblocking check (e.g., `epoll_wait` with no
//! timeout) sees it even in a busy loop: a timer file's expiry as it comes
//! due, and standard input as the console's interrupt brings it.
//!
//! Limits, which end the runner (the kernel sees it exit with
//! `EXIT_FAILURE`) rather than fail the program's call:
//! - A wait that nothing could end (no other thread to end it, no timeout,
//!   no armed timer, and no input that could arrive), where Linux would
//!   block forever.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use litebox::platform::ForkError;
use litebox::process::ProcessError;
use litebox::utils::TruncateExt as _;
use litebox_broker_protocol::process::{ProcessExitStatus, ProcessStartupData};
use litebox_common_linux::program_startup::{LinuxProcessStartup, LinuxProgramStartup};
use litebox_common_vm_abi::program::{self, ExitStatus, Program};
use litebox_common_vm_abi::{CallId, CallSet, LogLevel, Message, ProtSet, StartupInfo, UserRange};
use litebox_platform_vm_userland::process::ClonedProcess;
use litebox_platform_vm_userland::{VmUserland, kcall};
use litebox_shim_linux::{
    LinuxShim, LinuxShimBuilder, LinuxShimProcess, LoadedProgram, MemoryManager,
};

type Platform = VmUserland;

/// As other LiteBox Linux runners: a stable, non-root guest identity.
const GUEST_UID: u32 = 1000;
const GUEST_GID: u32 = 1000;

/// Besides [`CallId::Exit`] and [`CallId::ExitThread`], which are always
/// allowed. No key derivation: the process has no identity.
const SERVING_CALLS: CallSet = CallSet::EMPTY
    .with(CallId::ReplyAndWait)
    .with(CallId::Map)
    .with(CallId::Unmap)
    .with(CallId::Protect)
    .with(CallId::SetTimer)
    .with(CallId::Log)
    .with(CallId::Clone)
    .with(CallId::Futex)
    .with(CallId::InterruptThread);

/// [`SERVING_CALLS`] without `ReplyAndWait`, for a launched process, which has
/// no request to reply to.
const LAUNCHED_CALLS: CallSet = SERVING_CALLS.without(CallId::ReplyAndWait);

pub fn serve(info: &StartupInfo) -> ! {
    let platform: &'static Platform = Box::leak(Box::new(VmUserland::new(info)));
    let (local, startup, notifications) = litebox_broker_local_vm_userland::connect(info)
        .unwrap_or_else(|e| panic!("broker association: {e:?}"));
    kcall::restrict(CallSet::ALL.without(CallId::BrokerHandshake), ProtSet::ALL)
        .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let process_id = i32::try_from(process_id.0).expect("process ID fits pid_t");
    platform.set_notification_receiver(Box::leak(Box::new(notifications.into_receiver(
        litebox.broker_notification_dispatcher(),
        litebox.broker_failure_dispatcher(),
    ))));
    let shim = VmForkRunner::install(
        LinuxShimBuilder::new_with_litebox(platform, litebox, process_id),
        platform,
        info,
    )
    .build();
    match startup {
        Some(startup) => run_launched(&shim, process_id, initial_thread, &startup),
        None => serve_requests(info, &shim, process_id, initial_thread),
    }
}

/// Runs the program the kernel asks for, and replies with its exit status.
fn serve_requests(
    info: &StartupInfo,
    shim: &LinuxShim<Platform>,
    process_id: i32,
    initial_thread: litebox::thread::Thread,
) -> ! {
    let request = kcall::ready(VmUserland::upcall_entry_address())
        .unwrap_or_else(|status| panic!("ready: {status:?}"));
    kcall::restrict(SERVING_CALLS, ProtSet::ALL)
        .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
    if cfg!(debug_assertions) {
        check_process_clones(shim.litebox());
    }
    // Safety: mapped for the process's lifetime; the kernel writes it only
    // while the runner waits for a request.
    let window = unsafe { window(info.message_window) };
    let Program { path, argv, envp } = window
        .get(..request.len.trunc())
        .and_then(program::decode_request)
        .expect("the kernel sends a well-formed program");
    let task = litebox_common_linux::TaskParams {
        pid: process_id,
        uid: GUEST_UID,
        euid: GUEST_UID,
        gid: GUEST_GID,
        egid: GUEST_GID,
        blocked_signals: litebox_common_linux::signal::SigSet::empty(),
        ignored_signals: litebox_common_linux::signal::SigSet::empty(),
        inherited_fds: None,
        cwd: None,
        umask: None,
    };
    let program = shim
        .load_program(task, initial_thread, &path, argv, envp)
        .unwrap_or_else(|error| panic!("loading {path}: {error}"));
    let status = run(program).wait_for_exit_status();
    // For the broker process, whose exit the kernel completes once the runner
    // replies.
    let _ = shim.litebox().report_exit_status(status);
    let status = match status {
        ProcessExitStatus::Exited { code } => ExitStatus::Exited { code },
        ProcessExitStatus::Signaled { signal } => ExitStatus::Signaled { signal },
        _ => ExitStatus::Unknown,
    };
    let reply = program::encode_reply(status);
    window[..reply.len()].copy_from_slice(&reply);
    let _ = kcall::reply_and_wait(&Message {
        len: reply.len() as u64,
    });
    // One program per process.
    panic!("a request after the program's exit status")
}

/// Self-check (debug builds) of the kernel's process clones (see
/// `litebox_common_vm_abi`, `CloneKind::Process`), left for the kernel to end,
/// which its test client checks it freed, and of their adoption: a child of
/// `litebox`'s process runs only on the clone it has, its latest.
///
/// # Panics
///
/// On a failed check.
fn check_process_clones(litebox: &litebox::LiteBox<Platform>) {
    use litebox_common_vm_abi::{
        CloneKind, CloneRequest, NewThread, Status, encode_clone_descriptor,
    };
    let thread = NewThread {
        fs_base: 1,
        ..NewThread::default()
    };
    assert_eq!(
        kcall::call(&CloneRequest::new(CloneKind::Process, thread)),
        Err(Status::InvalidArgument)
    );
    // Never adopted, so they never run.
    let clone = || {
        kcall::clone_process()
            .expect("a process clone")
            .expect("an unadopted clone ran")
    };
    let replaced = clone();
    let pending = clone();
    assert!(pending > replaced, "a reused clone ID");
    // A child starts only on the clone the process has: not on one replaced
    // or never issued, nor with a malformed descriptor.
    let replaced = encode_clone_descriptor(replaced);
    let unissued = encode_clone_descriptor(pending + 1);
    let zero = encode_clone_descriptor(0);
    let pending = encode_clone_descriptor(pending);
    for descriptor in [&replaced[..], &unissued, &zero, &pending[..4]] {
        let child = litebox.allocate_child_process().expect("a child process");
        assert_eq!(
            child.start_with_existing_runner(descriptor, &[]),
            Err(ProcessError::PolicyDenied),
            "a child started with runner descriptor {descriptor:?}"
        );
    }
}

/// Runs the program `startup` names, in a launched process, and exits.
fn run_launched(
    shim: &LinuxShim<Platform>,
    process_id: i32,
    initial_thread: litebox::thread::Thread,
    startup: &ProcessStartupData,
) -> ! {
    // No request comes; this registers the upcall entry.
    kcall::ready(VmUserland::upcall_entry_address())
        .unwrap_or_else(|status| panic!("ready: {status:?}"));
    kcall::restrict(LAUNCHED_CALLS, ProtSet::ALL)
        .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
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
    } = match LinuxProcessStartup::decode(&startup.payload) {
        Ok(LinuxProcessStartup::Program(startup)) => startup,
        // The kernel supports no memory image; a `fork` clones the process.
        Ok(LinuxProcessStartup::Fork(_)) => panic!("a fork startup without a memory image"),
        Err(error) => panic!("invalid Linux process startup: {error:?}"),
    };
    let task = litebox_common_linux::TaskParams {
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
    };
    let program = shim
        .load_program(task, initial_thread, &path, argv, envp)
        .unwrap_or_else(|error| panic!("loading {path}: {error}"));
    let process = run(program);
    report_exit(shim, &process);
    if cfg!(debug_assertions) {
        use litebox_common_vm_abi::Status;
        // Self-check (see `check_process_clones`): a clone left for the kernel
        // to end as the process exits. Tolerates too little memory for the
        // clone (`NoMemory`) or for the kernel to write its ID (`Fault`).
        // After the report, which the broker keeps however the runner ends:
        // the kernel kills the runner if it cannot copy a page the clone
        // shares, and a failed check shows only in the log. Not in roots,
        // which cost more to clone once their program has run (e.g., too
        // much for `sched`'s timing under TCG).
        match kcall::clone_process() {
            Ok(Some(_)) | Err(Status::NoMemory | Status::Fault) => {}
            Ok(None) => panic!("an unadopted clone ran"),
            Err(status) => panic!("a process clone: {status:?}"),
        }
    }
    kcall::exit(process.wait_for_unix_shell_exit_code().cast_unsigned())
}

/// Starts the children of the program's `fork` in process clones (see the
/// [module](self) docs).
struct VmForkRunner {
    /// The shim's, which the clone's shim takes over.
    memory: Arc<MemoryManager<Platform>>,
    platform: &'static Platform,
    /// A copy, as the clone leaves the stack the original is on.
    info: StartupInfo,
}

impl VmForkRunner {
    /// Has `builder`'s shim start `fork` children in process clones.
    fn install(
        builder: LinuxShimBuilder<Platform>,
        platform: &'static Platform,
        info: &StartupInfo,
    ) -> LinuxShimBuilder<Platform> {
        let info = *info;
        // Safety: the clone's runner leaves the parent's at once, and uses
        // nothing of it but the program's memory manager and what the
        // platform keeps valid in a clone (see the module docs).
        unsafe {
            builder.with_native_fork_runner(|memory| Self {
                memory,
                platform,
                info,
            })
        }
    }
}

impl litebox_shim_linux::syscalls::process::ForkRunner<Platform> for VmForkRunner {
    /// Nothing: the kernel associates the clone, and makes its handshake as it
    /// adopts it.
    type ControlChannel = ();

    fn create_control_channel(
        &self,
        _child: &litebox::process::PendingChild,
    ) -> Result<(), ForkError<ProcessError>> {
        Ok(())
    }

    fn encode_runner_descriptor(
        &self,
        process: &ClonedProcess,
        (): &(),
    ) -> Result<Vec<u8>, ProcessError> {
        Ok(litebox_common_vm_abi::encode_clone_descriptor(process.id()).to_vec())
    }

    unsafe fn run_child(&self, (): ()) -> ! {
        // TODO: Free the parent runner's runtime (its shim, `LiteBox`, and
        // broker endpoint). As in the hosted runners' native fork, it stays in
        // the clone's heap, mostly owned by the stack frames the clone leaves.
        // Its endpoint works on the addresses of the clone's own ring and
        // shared buffers: dropping it would send the parent's requests (e.g.,
        // closing its handles) on the clone's association, and might wait on
        // locks of threads the clone lacks. Each generation of a fork chain
        // thus grows the runner heap by one runtime.
        let (memory, platform, info) = (self.memory.clone(), self.platform, self.info);
        // Safety: the clone's one thread is its main thread (see
        // `litebox_platform_vm_userland::process`), which never returns to
        // the frames it leaves.
        unsafe {
            litebox_platform_vm_userland::thread::run_on_main_stack(
                info.stack,
                Box::new(move || run_clone(platform, memory, &info)),
            )
        }
    }
}

/// A process clone's runner, on the main stack: continues the program as the
/// `fork` child its startup data describes.
fn run_clone(
    platform: &'static Platform,
    memory: Arc<MemoryManager<Platform>>,
    info: &StartupInfo,
) -> ! {
    let (local, startup, notifications) = litebox_broker_local_vm_userland::connect(info)
        .unwrap_or_else(|e| clone_failed(format_args!("broker association: {e:?}")));
    let startup = startup.unwrap_or_else(|| clone_failed(format_args!("no startup data")));
    let (litebox, process_id, initial_thread) =
        litebox::LiteBox::new_process_with_broker_local(platform, local);
    let process_id = i32::try_from(process_id.0)
        .unwrap_or_else(|_| clone_failed(format_args!("process ID {process_id:?}")));
    platform.set_notification_receiver(Box::leak(Box::new(notifications.into_receiver(
        litebox.broker_notification_dispatcher(),
        litebox.broker_failure_dispatcher(),
    ))));
    // Safety: `memory` is the program's, which only this shim uses: the
    // parent's runner, of which the clone has a copy, never runs here. No
    // lock of it is held (see `ForkLauncher::start`), and the platform
    // manages its mappings.
    let builder =
        unsafe { LinuxShimBuilder::new_for_native_fork(platform, litebox, process_id, memory) };
    let shim = VmForkRunner::install(builder, platform, info).build();
    // Safety: as above; the parent's shim sent `startup` for this clone.
    let program = unsafe { shim.restore_fork_from_native_clone(&startup.payload, initial_thread) }
        .unwrap_or_else(|error| clone_failed(format_args!("continuing the program: {error}")));
    let process = run(program);
    report_exit(&shim, &process);
    kcall::exit(process.wait_for_unix_shell_exit_code().cast_unsigned())
}

/// Ends a process clone that cannot continue the program, with the shell's
/// status for a command that cannot run.
fn clone_failed(why: core::fmt::Arguments<'_>) -> ! {
    kcall::log(
        LogLevel::Error,
        &alloc::format!("process clone failed: {why}"),
    );
    kcall::exit(127)
}

/// # Safety
///
/// `region` must be mapped for the process's lifetime, and accessed only
/// through the returned slice.
unsafe fn window(region: UserRange) -> &'static mut [u8] {
    let start: usize = region.start.trunc();
    // Safety: forwarded to the caller.
    unsafe { core::slice::from_raw_parts_mut(start as *mut u8, region.len.trunc()) }
}

/// Runs `program` until the guest process and all its threads exit, and
/// returns the process.
fn run(program: LoadedProgram<Platform>) -> LinuxShimProcess<Platform> {
    let LoadedProgram {
        entrypoints,
        process,
    } = program;
    // Safety: the guest's other threads are on other runner threads.
    unsafe {
        litebox_platform_vm_userland::thread::run_thread_ref(
            &entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // Detaches the thread, which ends the process once the others exit.
    drop(entrypoints);
    process.wait_for_exit_status();
    // The main thread replies, or exits, alone.
    litebox_platform_vm_userland::thread::join_all();
    process
}

/// Reports the exit status of the program `process` before the runner exits:
/// the broker keeps it over how the runner ends, i.e., its exit code, which
/// cannot tell a signal death from an exit, or a kill.
fn report_exit(shim: &LinuxShim<Platform>, process: &LinuxShimProcess<Platform>) {
    let _ = shim
        .litebox()
        .report_exit_status(process.wait_for_exit_status());
}
