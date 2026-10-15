// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Runs the one Linux program the kernel asks for, in the message format of
//! [`litebox_common_vm_abi::program`], and replies with its exit status.
//! The program's files, including standard streams, are the broker's.
//!
//! Lockdown: after the broker connects, no new association; once serving,
//! only [`SERVING_CALLS`]. Executable memory stays allowed, as a Linux
//! program may map code (W^X still holds).
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
use litebox::utils::TruncateExt as _;
use litebox_broker_protocol::process::ProcessExitStatus;
use litebox_common_vm_abi::program::{self, ExitStatus, Program};
use litebox_common_vm_abi::{CallId, CallSet, Message, ProtSet, StartupInfo, UserRange};
use litebox_platform_vm_userland::{VmUserland, kcall};
use litebox_shim_linux::{LinuxShim, LoadedProgram};

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

pub fn serve(info: &StartupInfo) -> ! {
    let platform: &'static Platform = Box::leak(Box::new(VmUserland::new(info)));
    let (local, notifications) = litebox_broker_local_vm_userland::connect(info)
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
    let shim =
        litebox_shim_linux::LinuxShimBuilder::new_with_litebox(platform, litebox, process_id)
            .build();

    let request = kcall::ready(VmUserland::upcall_entry_address())
        .unwrap_or_else(|status| panic!("ready: {status:?}"));
    kcall::restrict(SERVING_CALLS, ProtSet::ALL)
        .unwrap_or_else(|status| panic!("lockdown: {status:?}"));
    // Safety: mapped for the process's lifetime; the kernel writes it only
    // while the runner waits for a request.
    let window = unsafe { window(info.message_window) };
    let program = window
        .get(..request.len.trunc())
        .and_then(program::decode_request)
        .expect("the kernel sends a well-formed program");

    let status = run(&shim, process_id, initial_thread, program);
    let reply = program::encode_reply(status);
    window[..reply.len()].copy_from_slice(&reply);
    let _ = kcall::reply_and_wait(&Message {
        len: reply.len() as u64,
    });
    // One program per process.
    panic!("a request after the program's exit status")
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

/// Exits the runner if the program cannot be loaded.
fn run(
    shim: &LinuxShim<Platform>,
    process_id: i32,
    initial_thread: litebox::thread::Thread,
    program: Program,
) -> ExitStatus {
    let Program { path, argv, envp } = program;
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
    let LoadedProgram {
        entrypoints,
        process,
    } = shim
        .load_program(task, initial_thread, &path, argv, envp)
        .unwrap_or_else(|error| panic!("loading {path}: {error}"));
    // Safety: the guest's other threads are on other runner threads.
    unsafe {
        litebox_platform_vm_userland::thread::run_thread_ref(
            &entrypoints,
            &mut litebox_common_linux::PtRegs::default(),
        );
    }
    // Detaches the thread, which ends the process once the others exit.
    drop(entrypoints);
    let status = match process.wait_for_exit_status() {
        ProcessExitStatus::Exited { code } => ExitStatus::Exited { code },
        ProcessExitStatus::Signaled { signal } => ExitStatus::Signaled { signal },
        _ => ExitStatus::Unknown,
    };
    // The main thread replies alone.
    litebox_platform_vm_userland::thread::join_all();
    status
}
