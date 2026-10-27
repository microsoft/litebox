// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process groups and sessions.
//!
//! Every process belongs to one process group, and every process group to one
//! session. Each is identified by the ID of the process that created it, which
//! need not still exist. A child process starts in its creator's group and
//! session, while a root process, which has no creator, leads its own.
//!
//! A session may have a controlling terminal, whose events go to the session's
//! foreground process group, and a terminal controls at most one session. A
//! pseudo-terminal manager's handle refers to its subsidiary terminal in
//! process group requests.

use thiserror::Error;

use crate::{ObjectHandle, ProcessGroupId, ProcessId, SessionId};

/// A process's group and session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessGroupMembership {
    /// Process group.
    pub process_group: ProcessGroupId,
    /// Session.
    pub session: SessionId,
}

/// Request to move a process into a process group.
///
/// The target must be the caller or one of its children, or the broker returns
/// `UnknownObject`. The broker returns `PolicyDenied` if the target is in
/// another session than the caller or leads a session, or if `process_group`
/// is neither the target's ID nor an existing group in the caller's session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetProcessGroupRequest {
    /// Process to move.
    pub process_id: ProcessId,
    /// Group to join, which is created if its ID is `process_id`.
    pub process_group: ProcessGroupId,
}

/// Request to make a terminal the controlling terminal of the session that a
/// process leads, with the process's group in the foreground.
///
/// The target must be the caller or its pending child, or the broker returns
/// `UnknownObject`. Does nothing if the terminal already controls the target's
/// session. Otherwise the broker returns `PolicyDenied` if the target leads no
/// session, its session already has a controlling terminal, the terminal
/// controls another session, or the handle is not open for reading. Fails with
/// [`ProcessGroupError::NotControllingTerminal`] if the handle does not refer
/// to a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetControllingTerminalRequest {
    /// Process whose session acquires the terminal.
    pub process_id: ProcessId,
    /// Open handle to the terminal or to its pseudo-terminal manager.
    pub terminal: ObjectHandle,
}

/// Request to make a process group the foreground group of the caller's
/// controlling terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetForegroundGroupRequest {
    /// Open handle to the caller's controlling terminal or to its
    /// pseudo-terminal manager.
    pub terminal: ObjectHandle,
    /// Group to move to the foreground, which must be in the caller's session.
    pub process_group: ProcessGroupId,
}

/// Process group operation failure that is meaningful to the guest ABI.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProcessGroupError {
    #[error("object is not the caller's controlling terminal")]
    NotControllingTerminal,
    #[error("no such process group")]
    NoSuchProcessGroup,
    #[error("process group is not in the caller's session")]
    NotInSession,
}
