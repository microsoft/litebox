// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Supervision of the disposable shared-cache child.

use anyhow::{Context as _, Result, bail};
use std::{
    io::PipeReader,
    os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const FORWARDED: [i32; 4] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD];

struct SignalState {
    mask: libc::sigset_t,
    sigchld: Option<libc::sigaction>,
}

impl Drop for SignalState {
    fn drop(&mut self) {
        if let Some(action) = &self.sigchld {
            // SAFETY: restore the saved disposition before unblocking SIGCHLD.
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGCHLD, action, core::ptr::null_mut()) },
                0,
                "restoring SIGCHLD disposition"
            );
        }
        // SAFETY: this is the calling thread's previously returned signal mask.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const self.mask,
                    core::ptr::null_mut(),
                )
            },
            0,
            "restoring runner signal mask"
        );
    }
}

// Darwin discards default-ignored SIGCHLD even when it is blocked for sigwait.
// Installing a handler makes it waitable; blocking keeps the handler from running.
extern "C" fn sigchld_wakeup(_: i32) {}

fn start_parent_watch(reader: PipeReader) -> Result<()> {
    let ready = Arc::new(AtomicBool::new(false));
    let publish = ready.clone();
    let watcher = std::thread::Builder::new()
        .name("litebox-parent-watch".into())
        .spawn(move || {
            let mut signals = 0;
            // SAFETY: signals is writable; only this watchdog's mask is changed.
            // Guest/termination signals must be delivered to the executing threads.
            unsafe {
                libc::sigfillset(&raw mut signals);
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_BLOCK,
                        &raw const signals,
                        core::ptr::null_mut()
                    ),
                    0
                );
            }
            let fd = reader.into_raw_fd();
            publish.store(true, Ordering::Release);
            // SAFETY: fd is this thread's owned pipe read end. After publication,
            // no libSystem call or Rust destructor runs here while the cache changes.
            unsafe { watch_parent(fd) }
        })
        .context("starting parent-liveness watcher")?;
    while !ready.load(Ordering::Acquire) {
        if watcher.is_finished() {
            bail!("parent-liveness watcher exited before publication");
        }
        std::thread::yield_now();
    }
    // The watcher owns its descriptor and lives until this disposable process exits.
    drop(watcher);
    Ok(())
}

// Stay entirely outside libSystem: the main thread may be replacing its code.
#[unsafe(naked)]
unsafe extern "C" fn watch_parent(_: libc::c_int) -> ! {
    core::arch::naked_asm!(
        "mov x19, x0",
        "sub sp, sp, #16",
        "1:",
        "mov x0, x19",
        "mov x1, sp",
        "mov x2, #1",
        "mov x16, #3", // Darwin read
        "svc #0x80",
        "b.cc 2f",
        "cmp x0, #{eintr}",
        "b.eq 1b",
        "b 3f", // Read errors fail closed, too.
        "2:",
        "cbnz x0, 1b",
        "3:",
        "mov x0, #{status}",
        "mov x16, #1", // Darwin exit: skip host teardown after guest execution.
        "svc #0x80",
        "udf #0",
        eintr = const libc::EINTR,
        status = const 128 + libc::SIGKILL,
    );
}

/// Return the exit status in the parent, or None in the child.
///
/// # Safety
/// Call only during single-threaded runner startup, before platform/broker
/// initialization, with no other child reapers. Only the child may proceed to
/// shared-cache publication.
pub(crate) unsafe fn fork_and_wait() -> Result<Option<i32>> {
    // Only the supervisor retains the writer. EOF detects every way it can
    // disappear, including SIGKILL, without relying on a reusable parent PID.
    let (reader, writer) = std::io::pipe().context("creating parent-liveness pipe")?;
    let mut signals = 0;
    let mut previous = 0;
    // SAFETY: both masks are writable stack storage. Block before fork so a
    // termination request cannot land between child creation and supervision.
    let error = unsafe {
        libc::sigemptyset(&raw mut signals);
        for signal in FORWARDED {
            libc::sigaddset(&raw mut signals, signal);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut previous)
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error)).context("blocking runner signals");
    }
    let mut restore = SignalState {
        mask: previous,
        sigchld: None,
    };
    // Also clear SIG_IGN/SA_NOCLDWAIT so the child's PID cannot be recycled
    // before it is reaped. Both branches restore the inherited disposition.
    // SAFETY: sigaction consists of zero-valid scalar fields.
    let mut action = unsafe { core::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = sigchld_wakeup as *const () as usize;
    let mut previous_action = action;
    // SAFETY: the initialized action matches the one-argument handler, and the
    // old action is writable. SIGCHLD is blocked throughout supervision.
    if unsafe { libc::sigaction(libc::SIGCHLD, &raw const action, &raw mut previous_action) } != 0 {
        return Err(std::io::Error::last_os_error()).context("installing SIGCHLD disposition");
    }
    restore.sigchld = Some(previous_action);
    // SAFETY: the caller guarantees single-threaded startup; both branches
    // restore the original mask, and the parent never enters guest code.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("forking macOS guest runner");
    }
    if pid == 0 {
        drop(writer);
        start_parent_watch(reader)?;
        return Ok(None);
    }
    drop(reader);
    let result = wait_for_child(pid, &signals);
    if result.as_ref().is_err_and(|error| {
        error
            .downcast_ref::<std::io::Error>()
            .is_none_or(|error| error.raw_os_error() != Some(libc::ECHILD))
    }) {
        // Do not leave an unsupervised child if waiting or forwarding fails.
        // SAFETY: auto-reaping is disabled and ECHILD was excluded above. This
        // child is still ours; SIGKILL also ends a child blocked in startup.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        loop {
            // SAFETY: pid names our child; no status output is requested.
            if unsafe { libc::waitpid(pid, core::ptr::null_mut(), 0) } >= 0
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
    }
    result.map(Some)
}

fn wait_for_child(pid: libc::pid_t, signals: &libc::sigset_t) -> Result<i32> {
    // Unlike Darwin sigwait, kevent does not defer unrelated fatal signals for
    // the duration of this wait. Their normal action closes the liveness pipe.
    // SAFETY: kqueue creates a new descriptor owned by this supervisor.
    let fd = unsafe { libc::kqueue() };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("creating supervisor kqueue");
    }
    // SAFETY: fd is the newly created, uniquely owned descriptor.
    let queue = unsafe { OwnedFd::from_raw_fd(fd) };
    let changes = FORWARDED.map(|signal| libc::kevent {
        ident: usize::try_from(signal).expect("positive signal number"),
        filter: libc::EVFILT_SIGNAL,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: core::ptr::null_mut(),
    });
    // SAFETY: changes is initialized; no event output is requested during registration.
    if unsafe {
        libc::kevent(
            queue.as_raw_fd(),
            changes.as_ptr(),
            4,
            core::ptr::null_mut(),
            0,
            core::ptr::null(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("registering supervisor signals");
    }
    loop {
        let mut status = 0;
        // SAFETY: pid names our fork child and status is writable output.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if waited == pid {
            if libc::WIFEXITED(status) {
                return Ok(libc::WEXITSTATUS(status));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(128 + libc::WTERMSIG(status));
            }
            // Traced children can report stops without WUNTRACED; they still
            // need supervision and must not be mistaken for reaped children.
            continue;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error).context("waiting for macOS guest runner");
        }
        let mut pending = 0;
        // SAFETY: pending is writable output. Only this thread consumes signals.
        if unsafe { libc::sigpending(&raw mut pending) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("querying pending supervisor signals");
        }
        if pending & signals == 0 {
            let mut event = changes[0];
            // SAFETY: event is writable output; registration precedes the pending
            // check, so an exit or forwarded signal cannot be lost before sleeping.
            let result = unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    core::ptr::null(),
                    0,
                    &raw mut event,
                    1,
                    core::ptr::null(),
                )
            };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                return Err(std::io::Error::last_os_error())
                    .context("waiting for supervisor signals");
            }
            continue;
        }
        let mut signal = 0;
        // SAFETY: at least one blocked signal is pending, so sigwait only drains
        // it; it never becomes the blocking wait that postpones other signals.
        let error = unsafe { libc::sigwait(signals, &raw mut signal) };
        if error == libc::EINTR {
            continue;
        }
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error))
                .context("waiting for runner signals");
        }
        if signal != libc::SIGCHLD {
            // SAFETY: this child has not been reaped, so its PID cannot be reused.
            // Forward only the caught signal, never a process-group-wide signal.
            if unsafe { libc::kill(pid, signal) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::ESRCH) {
                    bail!("forwarding signal {signal} to guest child: {error}");
                }
            }
        }
    }
}
