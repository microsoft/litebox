// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process groups and sessions.
//!
//! Every process belongs to one process group, and every process group to one
//! session. Each is identified by the ID of the process that created it, which
//! need not still exist. A child process starts in its creator's group and
//! session, while a root process, which has no creator, leads its own.

use crate::{ProcessGroupId, ProcessId, SessionId};

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
