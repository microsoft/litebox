// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Broker-hosted state for one Linux pidfd.
//!
//! # Why this exists
//!
//! pidfds carry process-exit notification: `pidfd_open(host_pid)`
//! returns an fd that becomes readable (POLLIN | POLLHUP) once the
//! target process exits. The shim's existing local-only pidfd path
//! (`EventFile::new_pidfd` in `litebox_shim_linux`) only works for
//! processes the local litebox process registry knows about; it
//! rejects pidfd_open for processes whose host worker lives in a
//! different runner process.
//!
//! Phase B / P2.B closes that gap by hosting the pidfd in the
//! broker. The broker calls `pidfd_open(host_pid)` once, polls it
//! with a dedicated background watcher thread, and fans out the
//! exit notification to every subscribed worker via the standard
//! [`SubscriptionList`] machinery. Workers receive the wake-up via
//! the [`crate::cwfd::subscription_list`] / `NotificationFrame`
//! path that already powers broker-backed eventfds.
//!
//! # Lifecycle
//!
//! [`PidfdState::new`] performs `pidfd_open(host_pid)` and spawns
//! the watcher thread. The thread blocks on `poll(pidfd, POLLIN, -1)`;
//! when it returns, the thread sets `exited = true` and notifies
//! subscribers with `NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP`, then
//! exits. The pidfd itself is closed when the `OwnedFd` drops with
//! the `PidfdState`.
//!
//! Per-pidfd thread is wasteful at large scale (10k child processes
//! → 10k threads) but is adequate for current test scenarios. A
//! shared-epoll pool can replace it when the working set grows.

use std::any::Any;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use litebox_common_linux::cwfd::notification_frame::{NOTIFY_EVENT_HUP, NOTIFY_EVENT_IN};
use litebox_common_linux::cwfd::notification_ring::NotificationSender;

use litebox_common_linux::cwfd::fd_transfer_frame::SubsystemTag;

use crate::cwfd::state_registry::StateObject;
use crate::cwfd::subscription_list::{SubscribeError, SubscriptionList, UnsubscribeError};

/// Errors `PidfdState` operations may return.
#[derive(Debug, thiserror::Error)]
pub enum PidfdError {
    #[error("pidfd_open({pid}) failed: {source}")]
    Open {
        pid: u32,
        #[source]
        source: std::io::Error,
    },
}

/// Broker-hosted state for one Linux pidfd watching `target_host_pid`.
#[derive(Debug)]
pub struct PidfdState {
    /// Target host PID this pidfd watches.
    target_host_pid: u32,
    /// Cached "process has exited" flag. Set by the watcher thread
    /// when `poll(pidfd, POLLIN)` returns; read by [`Self::exited`]
    /// for synchronous queries from RPC handlers.
    exited: AtomicBool,
    /// Subscription list — fans out `NOTIFY_EVENT_IN | HUP` to every
    /// subscribed worker once the watcher detects exit.
    subscriptions: SubscriptionList,
    /// Held to keep the kernel pidfd alive until the state object
    /// drops. The watcher thread holds its own copy via
    /// `try_clone()` (the thread closes its copy on exit; this one
    /// keeps the pidfd alive for synchronous queries that may race
    /// the watcher's exit notification).
    _pidfd: OwnedFd,
}

impl Drop for PidfdState {
    fn drop(&mut self) {
        // PE.9 invariant: always-on. A leak here means eager per-conn
        // unsubscribe isn't running for this state.
        assert!(
            self.subscriptions.is_empty(),
            "PidfdState (target_host_pid={}) dropped with {} live \
             subscription(s) — eager per-conn unsubscribe not running",
            self.target_host_pid,
            self.subscriptions.len()
        );
    }
}

impl PidfdState {
    /// Creates a new broker-hosted pidfd watching `target_host_pid`.
    /// Performs `pidfd_open(target_host_pid)` and spawns a background
    /// watcher thread that detects exit and fans out notifications.
    pub fn new(target_host_pid: u32) -> Result<Arc<Self>, PidfdError> {
        let pidfd = open_pidfd(target_host_pid)?;
        // Thread needs its own dup so its `OwnedFd` drop doesn't
        // close the pidfd while the state object is still answering
        // synchronous queries.
        let watcher_pidfd = pidfd.try_clone().map_err(|source| PidfdError::Open {
            pid: target_host_pid,
            source,
        })?;
        let state = Arc::new(Self {
            target_host_pid,
            exited: AtomicBool::new(false),
            subscriptions: SubscriptionList::new(),
            _pidfd: pidfd,
        });
        spawn_exit_watcher(Arc::clone(&state), watcher_pidfd);
        Ok(state)
    }

    /// Returns `true` once the watcher thread has observed the
    /// target process exit. Safe to call from any thread.
    pub fn exited(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }

    /// Target host PID. Exposed for diagnostics + telemetry.
    pub fn target_host_pid(&self) -> u32 {
        self.target_host_pid
    }

    /// Subscribes to events. Forwards to the underlying
    /// [`SubscriptionList`]. Immediately primes the new subscription
    /// with the current ready bits so workers that subscribe after
    /// exit don't miss the wake-up — matches Linux level-triggered
    /// poll semantics.
    pub fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        self.subscriptions
            .add(subscription_id, events_mask, sender)?;
        if self.exited() {
            self.subscriptions
                .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
        }
        Ok(())
    }

    /// Removes a subscription previously added via [`Self::subscribe`].
    pub fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        self.subscriptions.remove(subscription_id)
    }
}

impl StateObject for PidfdState {
    fn subsystem_tag(&self) -> SubsystemTag {
        SubsystemTag::Pidfd
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn subscribe(
        &self,
        subscription_id: u64,
        events_mask: u32,
        sender: Arc<Mutex<NotificationSender>>,
    ) -> Result<(), SubscribeError> {
        // Trait method delegates to the inherent method.
        PidfdState::subscribe(self, subscription_id, events_mask, sender)
    }
    fn unsubscribe(&self, subscription_id: u64) -> Result<(), UnsubscribeError> {
        PidfdState::unsubscribe(self, subscription_id)
    }
}

/// Opens a pidfd watching `target_host_pid` via the `pidfd_open(2)`
/// syscall. Wraps the raw fd in an `OwnedFd` for RAII closure.
fn open_pidfd(target_host_pid: u32) -> Result<OwnedFd, PidfdError> {
    // SAFETY: pidfd_open is a thin syscall wrapper; it returns a
    // fresh fd on success or -1 with errno set on failure. We
    // immediately wrap the returned fd in OwnedFd so Drop closes it
    // on every error path.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, target_host_pid as libc::pid_t, 0) };
    if raw < 0 {
        return Err(PidfdError::Open {
            pid: target_host_pid,
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: pidfd_open returned a valid fd we own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

/// Spawns a thread that blocks on `poll(pidfd, POLLIN, -1)` and
/// fires the `NOTIFY_EVENT_IN | HUP` subscription when poll returns
/// (which happens exactly once, on target-process exit). The thread
/// then exits.
fn spawn_exit_watcher(state: Arc<PidfdState>, pidfd: OwnedFd) {
    let target = state.target_host_pid;
    thread::Builder::new()
        .name(format!("pidfd-watch-{target}"))
        .spawn(move || {
            let mut pfd = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll(2) takes a pointer to a pollfd array; we
            // pass &mut to one initialised pollfd plus length 1.
            // POLLIN on a pidfd fires once on exit (and stays ready
            // thereafter); -1 means wait forever.
            let rc = unsafe { libc::poll(&raw mut pfd, 1, -1) };
            // poll returning <=0 here is unusual but possible (e.g.
            // EINTR if a signal interrupts). On EINTR we'd want to
            // retry; for the prototype we just bail and let the
            // synchronous `exited()` query stay false. A future
            // hardening pass should loop on EINTR.
            if rc <= 0 {
                tracing::warn!(
                    target_host_pid = target,
                    rc,
                    errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    "pidfd watcher: poll returned non-positive"
                );
                return;
            }
            state.exited.store(true, Ordering::SeqCst);
            state
                .subscriptions
                .notify(NOTIFY_EVENT_IN | NOTIFY_EVENT_HUP);
            // Drop pidfd here; the state's _pidfd keeps a separate
            // copy for any in-flight synchronous queries.
        })
        .expect("pidfd watcher thread spawn");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Sanity: opening a pidfd on a sleep child and watching it exit
    /// flips `exited()` to true within a reasonable bound.
    #[test]
    fn pidfd_state_detects_exit() {
        // Spawn a short-lived child via std::process so we control
        // its lifetime deterministically.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .expect("spawn /bin/sh");
        let pid = child.id();
        let state = PidfdState::new(pid).expect("PidfdState::new");
        // Reap so the child is actually gone (otherwise it's a zombie
        // and pidfd_open + poll behave consistently but the child is
        // still in the process table; doesn't affect this test's
        // success criterion).
        let _ = child.wait();
        // Spin up to 2s waiting for the watcher to flip the flag.
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if state.exited() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("PidfdState::exited never became true within 2s");
    }

    /// `exited()` is false immediately after construction for a
    /// child that hasn't exited yet.
    #[test]
    fn pidfd_state_not_exited_initially() {
        // Spawn a sleep child long enough to outlive the assertion.
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn /bin/sleep");
        let pid = child.id();
        let state = PidfdState::new(pid).expect("PidfdState::new");
        // Tiny grace period in case the watcher fires spuriously
        // (shouldn't happen — the child is sleeping).
        std::thread::sleep(Duration::from_millis(50));
        assert!(!state.exited(), "exited() must be false before child exits");
        // Cleanup.
        let _ = child.kill();
        let _ = child.wait();
    }
}
