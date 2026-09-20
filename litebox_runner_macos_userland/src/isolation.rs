// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Supervision of the disposable shared-cache child.

use anyhow::{Context as _, Result, bail};

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

/// Return the exit status in the parent, or None in the child.
///
/// # Safety
/// Call only during single-threaded runner startup, before platform/broker
/// initialization, with no other child reapers. Only the child may proceed to
/// shared-cache publication.
pub(crate) unsafe fn fork_and_wait() -> Result<Option<i32>> {
    let mut signals = 0;
    let mut previous = 0;
    // SAFETY: both masks are writable stack storage. Block before fork so a
    // termination request cannot land between child creation and supervision.
    let error = unsafe {
        libc::sigemptyset(&raw mut signals);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGCHLD] {
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
        return Ok(None);
    }
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
        let mut signal = 0;
        // SAFETY: these signals are blocked on this thread; signal is writable.
        // SIGCHLD closes the exit-before-wait race without polling.
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
