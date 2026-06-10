// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Shim-side accessor for the broker-hosted guest-pid provider.
//!
//! Mirrors the [`super::eventfd::broker_eventfd_provider`] pattern: a
//! process-global `OnceBox` holds an `Arc<dyn GuestPidProvider>`,
//! installed by the runner at bootstrap when an fd-token broker is
//! available. Shim call sites consult [`broker_guest_pid_provider`]
//! and fall back to per-shim allocation when the provider is unset.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use litebox::event::{Events, observer::Subject};
use litebox::process::ProcessId;
use litebox_common_linux::cwfd::broker_subscribable::BrokerEventCallback;
use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN};
use litebox_common_linux::guest_pid_provider::{
    GuestPidProvider, GuestPidProviderError, ProcessExitSubscription,
};
use litebox_platform_multiplex::Platform;

/// Process-global broker guest-pid provider. Set once at runner
/// bootstrap (in `litebox_runner_linux_userland`). `do_fork`
/// consults this; if `Some`, the broker allocates the child's pid;
/// if `None`, falls back to the local per-shim `ProcessRegistry`
/// counter — preserves existing single-worker behaviour when
/// fd-token transport is not configured.
static BROKER_GUEST_PID_PROVIDER: once_cell::race::OnceBox<Arc<dyn GuestPidProvider>> =
    once_cell::race::OnceBox::new();

/// Sets the process-global broker guest-pid provider. Called by the
/// runner exactly once during bootstrap. Returns `Err(provider)` if
/// a provider was already set; callers can decide whether to log +
/// drop or panic on that case (in practice it indicates a bootstrap
/// bug).
#[allow(dead_code)] // wired in by the runner bootstrap, not the shim itself
pub fn set_broker_guest_pid_provider(
    provider: Arc<dyn GuestPidProvider>,
) -> Result<(), alloc::boxed::Box<Arc<dyn GuestPidProvider>>> {
    BROKER_GUEST_PID_PROVIDER.set(alloc::boxed::Box::new(provider))
}

/// Returns the broker guest-pid provider if one has been set.
pub fn broker_guest_pid_provider() -> Option<Arc<dyn GuestPidProvider>> {
    BROKER_GUEST_PID_PROVIDER.get().cloned()
}

/// Shim-side wake source for a broker process-exit subscription.
pub struct BrokerProcessExitWake {
    pid: u32,
    subscription_id: u64,
    provider: Arc<dyn GuestPidProvider>,
    exited: Arc<AtomicBool>,
    /// Subject that downstream pidfd/wait code can observe exactly like
    /// the local process-registry exit subject.
    pub subject: Arc<Subject<Events, Events, Platform>>,
    /// Broker-cached exit code if the target had already exited when
    /// the subscription was installed.
    pub already_exited: Option<i32>,
}

impl BrokerProcessExitWake {
    /// Returns whether the broker has reported process exit to this wake source.
    pub fn is_exited(&self) -> bool {
        self.exited.load(Ordering::Acquire)
    }
}

impl Drop for BrokerProcessExitWake {
    fn drop(&mut self) {
        self.provider
            .unsubscribe_process_exit(self.pid, self.subscription_id);
    }
}

struct ProcessExitWaker {
    exited: Arc<AtomicBool>,
    subject: Arc<Subject<Events, Events, Platform>>,
}

impl BrokerEventCallback for ProcessExitWaker {
    fn on_events(&self, events: u32) {
        if events & (NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP) == 0 {
            return;
        }
        self.exited.store(true, Ordering::Release);
        self.subject.notify_observers(Events::IN | Events::HUP);
    }
}

/// Convenience: allocate a fresh globally-unique guest pid from the
/// broker if a provider is installed. Returns `None` if there's no
/// provider (caller falls back to the per-shim counter) or if the
/// broker RPC failed.
pub fn try_register_broker_guest_pid() -> Option<u32> {
    let provider = broker_guest_pid_provider()?;
    match provider.register_process() {
        Ok(pid) => Some(pid),
        Err(
            GuestPidProviderError::UnknownHandle
            | GuestPidProviderError::NotPermitted
            | GuestPidProviderError::Io,
        ) => None,
    }
}

/// Convenience: release a broker-allocated guest pid. No-op if no
/// provider is installed.
pub fn try_release_broker_guest_pid(pid: u32) {
    if let Some(provider) = broker_guest_pid_provider() {
        provider.release_process(pid);
    }
}

/// Convenience: mark `pid` exited in the broker-owned process state.
/// Exit teardown must proceed even if this best-effort RPC fails.
pub fn try_mark_broker_process_exited(pid: u32, exit_code: i32) {
    if let Some(provider) = broker_guest_pid_provider()
        && let Err(err) = provider.mark_process_exited(pid, exit_code)
    {
        log_unsupported!(
            "broker MarkProcessExited failed for pid {pid} status {exit_code}: {err:?}"
        );
    }
}

/// Block until the broker reports an exit on `pid`, returning the
/// stamped status code. Returns `None` if no broker provider is
/// installed, if the subscribe RPC fails, or if `timeout` elapses
/// before any stamp arrives.
///
/// Used by the fork-restore parent to wait on the runner's
/// install-complete signal: the parent allocates an auxiliary
/// broker process handle (via [`try_register_broker_guest_pid`]),
/// passes its pid to the runner via argv, then calls this helper
/// to block on the runner's `try_mark_broker_process_exited(aux_pid, status)`
/// stamp. A status of 0 means install succeeded; any non-zero status
/// is an errno-shaped failure code that the parent surfaces back to
/// the shim caller.
pub fn try_wait_broker_process_exit(pid: u32, timeout: core::time::Duration) -> Option<i32> {
    broker_guest_pid_provider()?.wait_process_exit_blocking(pid, timeout)
}

/// Convenience: stamp a setpgid with the broker if a provider is installed.
pub fn try_broker_set_pgid(
    caller_pid: u32,
    target_pid: u32,
    new_pgid: u32,
) -> Result<(), GuestPidProviderError> {
    if let Some(provider) = broker_guest_pid_provider() {
        provider.set_pgid(caller_pid, target_pid, new_pgid)
    } else {
        Ok(())
    }
}

/// Convenience: stamp a setsid with the broker if a provider is installed.
pub fn try_broker_set_sid(caller_pid: u32) -> Result<u32, GuestPidProviderError> {
    if let Some(provider) = broker_guest_pid_provider() {
        provider.set_sid(caller_pid)
    } else {
        Ok(caller_pid)
    }
}

/// Phase F.5+ PE.1 Step D: release every (pid, *) entry the broker
/// is tracking on the worker's control connection. Best-effort; exit
/// teardown must proceed if the RPC fails. Called from
/// `prepare_for_exit` after the per-fd `close_all_fds` pass — that
/// pass releases broker-backed fd refs explicitly via on_close, and
/// this RPC is the belt-and-braces sweep for anything that wasn't
/// covered (non-fd state like ProcessState refs, future broker-held
/// resources not tracked through the fd table). It's a no-op when
/// per-pid tracking is gated off (caller_pid=0) because the broker
/// has no per-pid buckets to release.
pub fn try_release_all_broker_for_pid(pid: u32) {
    if let Some(provider) = broker_guest_pid_provider() {
        match provider.release_all_for_pid(pid) {
            Ok(0) => {}
            Ok(_n) => {
                // Silent on success path — release count is for
                // diagnostics only and would be very chatty.
            }
            Err(err) => {
                log_unsupported!("broker ReleaseAllForPid failed for pid {pid}: {err:?}");
            }
        }
    }
}

/// Subscribe to broker-owned process exit for a guest [`ProcessId`].
///
/// Phase B.2 can use the returned [`BrokerProcessExitWake::subject`] as
/// the pidfd/wait wake source and [`BrokerProcessExitWake::is_exited`]
/// (plus `already_exited`) for immediate readiness.
pub fn try_subscribe_broker_process_exit(process_id: ProcessId) -> Option<BrokerProcessExitWake> {
    let provider = broker_guest_pid_provider()?;
    let pid = process_id.0;
    let exited = Arc::new(AtomicBool::new(false));
    let subject = Arc::new(Subject::new());
    let callback: Arc<dyn BrokerEventCallback> = Arc::new(ProcessExitWaker {
        exited: Arc::clone(&exited),
        subject: Arc::clone(&subject),
    });
    let ProcessExitSubscription {
        subscription_id,
        already_exited,
    } = match provider.subscribe_process_exit(pid, NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP, callback) {
        Ok(sub) => sub,
        Err(err) => {
            log_unsupported!("broker SubscribeProcessExit failed for pid {pid}: {err:?}");
            return None;
        }
    };
    if already_exited.is_some() {
        exited.store(true, Ordering::Release);
        subject.notify_observers(Events::IN | Events::HUP);
    }
    Some(BrokerProcessExitWake {
        pid,
        subscription_id,
        provider,
        exited,
        subject,
        already_exited,
    })
}
