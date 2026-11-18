// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed, process-shared memory objects. Caller credentials are bound to
//! the process by the deployment, never supplied on the wire.

use crate::ProcessId;
use crate::fs::{FileError, FileUser, MapFileResponse};

wire_struct! {
    /// Metadata of one segment. Times are seconds since the Unix epoch, or zero
    /// for events that have not occurred.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SegmentStatus {
        /// Published key, or zero for a private or deleted segment.
        pub key: i32,
        /// Requested byte length, before rounding to pages.
        pub size: u64,
        /// Immutable creating identity.
        pub creator: FileUser,
        /// Current owning identity.
        pub owner: FileUser,
        /// Owner/group/other permission bits.
        pub mode: u16,
        /// Creator's PID as seen by this caller, or zero when not visible.
        pub creator_pid: u32,
        /// Last attaching/detaching PID, or zero when unknown or not visible.
        pub last_pid: u32,
        /// Total confirmed attachments in all processes.
        pub attachments: u64,
        /// Creation or most recent metadata change.
        pub created: u64,
        /// Most recent attach.
        pub attached: u64,
        /// Most recent detach.
        pub detached: u64,
        /// Whether deletion is pending the last detach or provisional attachment.
        pub removed: bool,
    }
}

/// One provisional attachment, scoped to the requesting process.
///
/// This is distinct from the host handle delivery token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentAttachId(pub u64);

wire_newtype!(SegmentAttachId: u64);

wire_enum! {
    /// Operations on the caller's segment namespace or existing attachments.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SegmentRequest {
        /// Looks up a key, optionally creating a segment. Key zero always creates.
        Get {
            key: i32,
            size: u64,
            mode: u16,
            create: bool,
            exclusive: bool,
        },
        /// Reads the object's metadata.
        Status { id: u32 },
        /// Changes owner and permission bits, preserving creator identity.
        Set { id: u32, owner: FileUser, mode: u16 },
        /// Unpublishes the key and deletes the object once no attachments or reservations remain.
        Delete { id: u32 },
        /// Reserves an attachment and delivers the backing object without changing metadata.
        Attach { id: u32, writable: bool },
        /// Releases one attachment held by this process, even after a namespace switch.
        Detach { id: u32 },
        /// Moves self or a pending child to an empty namespace.
        NewNamespace { target: ProcessId },
        /// Copies attachment counts to a pending child inheriting its parent's VM.
        Inherit { target: ProcessId },
        /// Records a reserved attachment after the caller has mapped the backing object.
        ConfirmAttach { attachment: SegmentAttachId },
        /// Releases an unused reservation without recording an attach or detach.
        CancelAttach { attachment: SegmentAttachId },
        /// Adjusts a confirmed attachment count after splitting or releasing mapped regions.
        AdjustAttachments { id: u32, delta: i64 },
    }
}

wire_enum! {
    /// Successful operation, or an ordinary (recoverable) guest error.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SegmentResponse {
        /// Result of a successful lookup or creation.
        Id(u32),
        /// Current metadata.
        Status(SegmentStatus),
        /// Reserved attachment, backing-object delivery information, and unrounded length.
        AttachPrepared {
            attachment: SegmentAttachId,
            mapping: MapFileResponse,
            size: u64,
        },
        /// The requested change was made.
        Done,
        /// Caller-visible failure.
        Failed(FileError),
    }
}
