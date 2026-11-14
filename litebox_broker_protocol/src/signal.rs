// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Signals sent between broker processes, and changes to their children
//! reported to parents.
//!
//! Besides the signals processes send, a process can receive one when its
//! parent exits (see [`crate::message::ProcessRequest::SetParentExitSignal`]).
//!
//! Signals are numbered from one to [`MAX_SIGNAL`]. The broker keeps at most
//! one pending instance of each signal per process, and of each signal per
//! thread for signals sent to one thread, so repeated signals coalesce until
//! the process takes them. Child events coalesce the same way:
//! a parent has at most one pending child exit, the earliest since it last
//! took one, and at most one pending child removal.

use crate::process::ChildExit;
use crate::{ObjectHandle, ProcessGroupId, ProcessId, ThreadId};

/// Largest signal number the broker delivers.
pub const MAX_SIGNAL: u32 = 64;

/// Process, processes, or thread a signal is sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalTarget {
    /// One process.
    Process(ProcessId),
    /// One thread.
    Thread {
        /// Process the thread belongs to.
        process: ProcessId,
        /// Thread to signal.
        thread: ThreadId,
    },
    /// Every process in a process group.
    ProcessGroup(ProcessGroupId),
    /// Every process in the caller's PID namespace except the caller itself
    /// and the namespace's first process.
    All,
}

/// Request to send a signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendSignalRequest {
    /// Target processes or thread.
    ///
    /// The broker returns `UnknownObject` if no process or thread is
    /// targeted.
    pub target: SignalTarget,
    /// Signal number, or zero to only check that a target exists.
    ///
    /// The broker returns `UnsupportedOperation` for a number above
    /// [`MAX_SIGNAL`].
    pub signal: u32,
}

/// Response to a request opening the caller's signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenSignalsResponse {
    /// Handle that becomes readable while signals or child events are pending.
    pub handle: ObjectHandle,
}

/// Request to take one of the caller's pending signals, its pending child
/// exit, or its pending child removal.
///
/// The broker returns `WouldBlock` when none is pending.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeSignalRequest {
    /// Handle returned by the open request.
    pub handle: ObjectHandle,
}

/// One event taken from the caller's signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalEvent {
    /// The ABI-neutral terminal actions posted to the caller's initially
    /// attached process group since the caller last took them.
    Terminal(crate::terminal::TerminalEvents),
    /// A signal another process sent to the caller or one of its threads.
    Signal(PendingSignal),
    /// The earliest child exit since the caller last took one.
    ChildExited(ChildExit),
    /// One or more children left the caller without exiting since it last
    /// took this event, such as a child whose startup failed.
    ///
    /// A collection that found only such children live no longer finds them.
    ChildRemoved,
}

/// A signal taken from the caller's pending signals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingSignal {
    /// The caller's thread the signal was sent to, which may have ended
    /// since, or `None` if it was sent to the caller.
    pub thread: Option<ThreadId>,
    /// Signal number, from one to [`MAX_SIGNAL`].
    pub signal: u32,
    /// Process that first sent the signal while it was pending, such as the
    /// exiting parent that sent a parent-exit signal.
    pub sender: ProcessId,
}
