// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-subsystem fd migration policy gate for fork/exec paths.
//!
//! # Why this module exists
//!
//! Litebox supports three structurally distinct fork/exec entry points,
//! each of which has to do *something* with every open guest fd:
//!
//! * **`do_fork` (independent / kernel CoW)** — real kernel fork via
//!   the host. Linux duplicates the fd table for us, so there is no
//!   per-subsystem migration code path at all. (See
//!   [`process::Task::do_fork`].)
//! * **`commit_delayed_fork` (vfork-style delayed fork)** — snapshot
//!   the child's fd table into a `FdTableSnapshot` and restore it in
//!   a freshly spawned worker host. The per-fd accept/reject decision
//!   lives in [`process::Task::snapshot_fd_table`], which exhaustively
//!   matches on [`FdClass`] (the canonical fork-path gate today).
//! * **`exec_on_remote_host` (cross-binary-type exec)** — when a
//!   non-PIE binary is `execve`'d we spawn a fresh worker host and
//!   hand it `--broker-fd-bridge` specs for every fd that should
//!   survive the exec. Historically each subsystem had its own
//!   per-type filter loop in `exec_on_remote_host`, with **no
//!   compile-time enforcement** that every [`RawFdRef`] variant got
//!   one. The epoll/inotify migration regression
//!   (commit `5387acc3`, 68/99 hard FAILs) was a direct consequence:
//!   two new subsystems were added without matching filter loops, and
//!   the gap was only caught by integration tests.
//!
//! This module turns "every subsystem has a policy for every
//! fork/exec path" into a **compile-time** invariant. Adding a new
//! variant to [`RawFdRef`] is rejected at this gate (rustc E0004 +
//! the workspace-wide `clippy::wildcard_enum_match_arm = "deny"`),
//! forcing the author to make an explicit per-path policy decision
//! at one place — this module — and the policy decision is then
//! self-documenting code visible alongside the rest of the migration
//! decision surface.
//!
//! # How the gate works
//!
//! Each of the three fork/exec entry points contains a single
//! `migration_policy::reference_gate::<FS>()` call (a zero-cost
//! `const fn` pointer reference) whose only purpose is to keep this
//! module in the build dependency graph. The actual gate is
//! [`migration_policies_for`]: a `const fn` with one match arm per
//! [`RawFdRef`] variant, returning a [`PerFdMigrationPolicies`]
//! record that documents — for each fork path — what happens to a
//! fd of that kind.
//!
//! # Invariant
//!
//! No catch-all `_` arms. No `#[allow(clippy::wildcard_enum_match_arm)]`.
//! Every variant must be named explicitly. Adding a new [`RawFdRef`]
//! variant **must** fail to compile here, and the author must add an
//! arm that either:
//!
//! 1. Picks [`WorkerExecMigrationPolicy::BridgedByLoop`] and points
//!    at the corresponding emit loop in
//!    [`process::Task::exec_on_remote_host`] (and adds that loop if
//!    it doesn't exist).
//! 2. Picks [`WorkerExecMigrationPolicy::NotBridged`] with a clear
//!    [`NoBridgeReason`] documenting why exec-time bridging is a
//!    no-op or unsupported for this fd kind.
//!
//! The same is required for [`DelayedForkPolicy`] and
//! [`IndependentForkPolicy`].

use crate::syscalls::process;
use crate::{RawFdRef, ShimFS};

/// Per-subsystem migration policy decisions, one record per fork
/// path. Returned by [`migration_policies_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PerFdMigrationPolicies {
    /// Policy for the cross-binary-type `execve` path
    /// (`exec_on_remote_host` in `process.rs`).
    pub(crate) worker_exec: WorkerExecMigrationPolicy,
    /// Policy for the vfork-style delayed-fork commit
    /// (`commit_delayed_fork` / `snapshot_fd_table` in `process.rs`).
    pub(crate) delayed_fork: DelayedForkPolicy,
    /// Policy for the independent / kernel-CoW fork
    /// (`do_fork` in `process.rs`).
    pub(crate) independent_fork: IndependentForkPolicy,
}

/// Policy for an fd kind when crossing a non-PIE worker-host exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerExecMigrationPolicy {
    /// The corresponding `exec_on_remote_host` loop emits a
    /// `--broker-fd-bridge` spec so the new worker re-attaches.
    ///
    /// `loop_name` **must** be a `pub(crate) const &str` exported by
    /// [`crate::syscalls::process`] (e.g.
    /// [`crate::syscalls::process::EPOLL_BRIDGE_LOOP_NAME`]). The typed
    /// path ensures that renaming or removing the emit loop without
    /// updating this arm fails to compile (unresolved path) — closing
    /// the "dishonest attestation" gap where a hand-typed string could
    /// claim a loop that does not exist.
    BridgedByLoop {
        /// Short identifier for the emit block. Must reference one of
        /// the `*_BRIDGE_LOOP_NAME` constants in
        /// [`crate::syscalls::process`].
        loop_name: &'static str,
    },
    /// Not bridged across exec. The fd is intentionally dropped (in
    /// effect close-on-exec equivalent) or is structurally invalid
    /// past the exec point.
    NotBridged {
        /// Why this kind has no bridging logic.
        reason: NoBridgeReason,
    },
}

/// Policy for an fd kind when crossing a vfork-style delayed-fork
/// commit. Today every accept/reject decision is taken by
/// `snapshot_fd_table`'s exhaustive `FdClass` match; this enum
/// records that linkage at the [`RawFdRef`] level so the two gates
/// (RawFdRef + FdClass) stay in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelayedForkPolicy {
    /// The fd is serialized into the `FdTableSnapshot` and restored
    /// on the new worker host. `snapshot_fd_table` decides whether
    /// the fd is accepted or rejected based on its `FdClass`.
    SnapshottedByFdClass,
    /// The fd kind cannot be created by guest code on the default
    /// non-`worker_local_inet` build, so the arm exists for
    /// compile-time gating only and is never reached at runtime.
    #[allow(dead_code)] // only constructed under cfg(feature = "worker_local_inet")
    CfgOnlyVariant,
}

/// Policy for an fd kind when crossing an independent (kernel) fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndependentForkPolicy {
    /// The host kernel duplicates the underlying file description as
    /// part of `fork(2)` / `clone(2)`. No shim-side migration is
    /// required — the child sees the same fd table as the parent.
    KernelInherits,
    /// The fd is backed by a broker handle whose refcount is bumped
    /// by `clone_for_fork`'s `on_dup` callback (so the child's later
    /// close path balances the parent's `on_close`). No additional
    /// per-fork migration step is required because the dup happens
    /// in the descriptor table layer.
    BrokerHandleDupViaOnDup,
    /// Same compile-time-only variant case as
    /// [`DelayedForkPolicy::CfgOnlyVariant`].
    #[allow(dead_code)] // only constructed under cfg(feature = "worker_local_inet")
    CfgOnlyVariant,
}

/// Reason why a particular fd kind has no `exec_on_remote_host`
/// bridge logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoBridgeReason {
    /// The fd is backed by a host kernel object (e.g. a real Linux
    /// pipe end via `HostPassthroughFd`) that is dup'd into the
    /// child by `posix_spawn` file actions, so no shim-side bridge
    /// spec is needed.
    HostKernelDupAcrossExec,
    /// Shim-local Unix domain socket (no broker backing). Cross-
    /// worker connected/socketpair state isn't preserved by design;
    /// the broker-backed variants (`BrokerSocketPair` etc.) are the
    /// migratable counterpart.
    NoCrossWorkerStatePreservation,
    /// Broker-backed datagram socket. Migration support is not
    /// wired up yet; convert to `BridgedByLoop` when it lands.
    BrokerStateNotYetMigratable,
    /// Compile-time-only arm: variant only exists under a cfg gate
    /// the production build does not enable.
    #[allow(dead_code)] // reserved for future cfg-gated NotBridged arms
    CfgGatedVariant,
}

/// The single shared enumeration: every [`RawFdRef`] variant maps to
/// its per-fork-path migration policies.
///
/// **Do not add a wildcard arm.** Adding a new variant to
/// [`RawFdRef`] must fail to compile here; the author must make an
/// explicit policy decision for each fork path.
#[must_use]
pub(crate) fn migration_policies_for<FS: ShimFS>(r: &RawFdRef<'_, FS>) -> PerFdMigrationPolicies {
    match r {
        // Regular filesystem fd. Migrated across worker-exec via the
        // `fs_fds` brokerfile loop in `exec_on_remote_host`.
        RawFdRef::Fs(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::FS_BROKERFILE_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::KernelInherits,
        },
        // Legacy `worker_local_inet` smoltcp socket. Only compiles
        // under the `worker_local_inet` feature; production builds
        // omit the variant entirely.
        #[cfg(feature = "worker_local_inet")]
        RawFdRef::Net(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::NETWORK_TCP_LISTEN_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::CfgOnlyVariant,
            independent_fork: IndependentForkPolicy::CfgOnlyVariant,
        },
        // eventfd / timerfd / pidfd all share `EventfdSubsystem`.
        // Two separate emit loops handle eventfd promotion and
        // timerfd snapshot respectively.
        RawFdRef::Eventfd(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::EVENTFD_AND_TIMERFD_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        // epoll. Snapshot interest list and re-add per-interest in
        // the new worker. The corresponding emit loop MUST stay
        // last in `exec_on_remote_host` (see invariant note there).
        RawFdRef::Epoll(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::EPOLL_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::KernelInherits,
        },
        // Shim-local Unix domain socket (no broker backing). Not
        // migrated across worker-exec; broker-backed counterparts
        // (`BrokerSocketPair`, `BrokerTcpConn`, ...) are.
        RawFdRef::Unix(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::NotBridged {
                reason: NoBridgeReason::NoCrossWorkerStatePreservation,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::KernelInherits,
        },
        // Host-backed kernel fd (a real Linux pipe end imported
        // from a prior delayed-fork bridge). `posix_spawn` file
        // actions dup it into the child; no shim spec needed.
        RawFdRef::HostPassthroughFd(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::NotBridged {
                reason: NoBridgeReason::HostKernelDupAcrossExec,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::KernelInherits,
        },
        // Broker-backed pipe. Emit-side `dup_handle` + bridge spec;
        // post-spawn release tracked in `broker_pipe_transit_release`.
        RawFdRef::BrokerPipe(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::BROKER_PIPE_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::BrokerSocketPair(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::BROKER_SOCKETPAIR_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::BrokerTcpConn(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::BROKER_TCP_CONN_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::BrokerPty(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::BROKER_PTY_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::Signalfd(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::SIGNALFD_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::Inotify(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::INOTIFY_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        RawFdRef::BrokerInetListener(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::BridgedByLoop {
                loop_name: process::BROKER_INET_LISTENER_BRIDGE_LOOP_NAME,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        // Broker-hosted datagram socket. No exec bridge yet (kernel
        // state lives in the broker; migration would need additional
        // wiring). Lift into a `BridgedByLoop` arm when support lands.
        RawFdRef::BrokerInetDgram(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::NotBridged {
                reason: NoBridgeReason::BrokerStateNotYetMigratable,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
        // Broker-hosted raw IP socket (e.g. ICMP). Same status as
        // BrokerInetDgram: parked until cross-worker raw-socket
        // state preservation is wired up.
        RawFdRef::BrokerInetRaw(_) => PerFdMigrationPolicies {
            worker_exec: WorkerExecMigrationPolicy::NotBridged {
                reason: NoBridgeReason::BrokerStateNotYetMigratable,
            },
            delayed_fork: DelayedForkPolicy::SnapshottedByFdClass,
            independent_fork: IndependentForkPolicy::BrokerHandleDupViaOnDup,
        },
    }
}

/// Zero-cost reference to keep this module wired into the build at
/// each fork-path entry point. Calling
/// `let _ = reference_gate::<FS>;` at the top of `do_fork`,
/// `commit_delayed_fork`, and `exec_on_remote_host` ensures the
/// compile-time gate cannot be elided by dead-code stripping and
/// makes the dependency visible to readers of those functions.
#[inline]
pub(crate) fn reference_gate<FS: ShimFS>() -> fn(&RawFdRef<'_, FS>) -> PerFdMigrationPolicies {
    migration_policies_for::<FS>
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All `BridgedByLoop` loop labels are now typed paths to
    /// `pub(crate) const &str` items in [`crate::syscalls::process`].
    /// Renaming/removing a constant without updating both the policy
    /// arm and the emit loop fails to compile (unresolved path), so
    /// the previous hand-typed-string smoke test became redundant.
    ///
    /// This test is retained as **documentation** of the canonical
    /// loop-name set; it also pins string values that test-coverage
    /// gates may grep for.
    #[test]
    fn worker_exec_loop_labels_are_documented() {
        let labels = [
            process::FS_BROKERFILE_BRIDGE_LOOP_NAME,
            process::EVENTFD_AND_TIMERFD_BRIDGE_LOOP_NAME,
            process::EPOLL_BRIDGE_LOOP_NAME,
            process::BROKER_PIPE_BRIDGE_LOOP_NAME,
            process::BROKER_SOCKETPAIR_BRIDGE_LOOP_NAME,
            process::BROKER_TCP_CONN_BRIDGE_LOOP_NAME,
            process::BROKER_PTY_BRIDGE_LOOP_NAME,
            process::SIGNALFD_BRIDGE_LOOP_NAME,
            process::INOTIFY_BRIDGE_LOOP_NAME,
            process::BROKER_INET_LISTENER_BRIDGE_LOOP_NAME,
        ];
        for label in labels {
            assert!(!label.is_empty(), "loop label must be non-empty");
        }
    }
}
