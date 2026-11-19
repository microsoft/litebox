// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed, process-shared memory segments. The deployment binds each
//! association's segment credential; requests never carry one.

use crate::fs::{FileUser, MapFileResponse};

wire_struct! {
    /// Metadata of one segment. Times are seconds since the Unix epoch, or zero
    /// for events that have not occurred.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SegmentStatus {
        /// Published key, or zero for a private or removed segment.
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
        pub change_time: u64,
        /// Most recent attach.
        pub attach_time: u64,
        /// Most recent detach.
        pub detach_time: u64,
        /// Whether removal waits for the last attachment or provisional attachment to end.
        pub removed: bool,
    }
}

/// One provisional attachment, scoped to the requesting process.
///
/// This is distinct from the host handle delivery token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SegmentAttachId(pub u64);

wire_newtype!(SegmentAttachId: u64);

wire_struct! {
    /// Looks up a key in the caller's namespace, optionally creating a segment.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetSegmentRequest {
        /// The key to look up, or zero to always create a private segment.
        pub key: i32,
        /// Byte length of a new segment; an existing one must be at least this long.
        pub size: u64,
        /// Permission bits of a new segment, and the access an existing one must grant.
        pub mode: u16,
        /// Create a segment if the key has none.
        pub create: bool,
        /// With `create`, fail if the key already has a segment.
        pub exclusive: bool,
    }
}

wire_struct! {
    /// Changes a segment's owner and permission bits, preserving its creator.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetSegmentRequest {
        /// The segment.
        pub id: u32,
        /// The new owning identity.
        pub owner: FileUser,
        /// The new permission bits.
        pub mode: u16,
    }
}

wire_struct! {
    /// Reserves an attachment and delivers the segment's backing object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PrepareSegmentAttachRequest {
        /// The segment.
        pub id: u32,
        /// Whether the attachment may write.
        pub writable: bool,
    }
}

wire_struct! {
    /// A reserved attachment, with the delivered backing object.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PreparedSegmentAttach {
        /// Names the reservation to confirm or cancel.
        pub attachment: SegmentAttachId,
        /// The delivered backing object, covering the page-rounded segment.
        pub mapping: MapFileResponse,
        /// The segment's byte length, before rounding to pages.
        pub size: u64,
    }
}

wire_struct! {
    /// Replaces how many attachments the caller holds of one segment.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetSegmentAttachmentsRequest {
        /// The segment.
        pub id: u32,
        /// The caller's new total, which only confirmed attaches and their splits
        /// can raise above zero.
        pub count: u64,
    }
}
