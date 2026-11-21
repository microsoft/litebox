// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed, process-shared memory segments. The deployment binds each
//! association's segment credential; requests never carry one.

use thiserror::Error;

use crate::fs::{FileUser, MapFileResponse};

/// Names one segment, unique across namespaces while it lives.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SegmentId(pub u32);

wire_newtype!(SegmentId: u32);

wire_enum! {
    /// Segment operation failure that is meaningful to the guest.
    #[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
    pub enum SegmentError {
        #[error("the deployment provides no segments")]
        Unavailable,
        #[error("the key already has a segment")]
        Exists,
        #[error("the key has no segment")]
        Missing,
        #[error("invalid segment ID, size, attachment or count")]
        InvalidArgument,
        #[error("insufficient access rights")]
        AccessDenied,
        #[error("not the segment's owner or creator")]
        NotOwner,
        #[error("segment capacity exhausted")]
        NoSpace,
        #[error("segment backing store failed")]
        Io,
    }
}

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
        pub id: SegmentId,
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
        pub id: SegmentId,
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
    /// How many attachments the caller holds of one segment.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct SegmentAttachmentCount {
        /// The segment.
        pub id: SegmentId,
        /// The caller's new total, which only confirmed attaches and their splits
        /// can raise above zero.
        pub count: u64,
    }
}

/// Up to [`Self::CAPACITY`] attachment counts, replaced together.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SegmentAttachmentCounts {
    len: u8,
    entries: [SegmentAttachmentCount; Self::CAPACITY],
}

impl SegmentAttachmentCounts {
    /// How many counts one request carries; more take further requests.
    pub const CAPACITY: usize = 6;

    /// Collects `counts`, or returns `None` if there are more than
    /// [`Self::CAPACITY`].
    #[must_use]
    pub fn new(counts: &[SegmentAttachmentCount]) -> Option<Self> {
        let mut entries = [SegmentAttachmentCount::default(); Self::CAPACITY];
        entries.get_mut(..counts.len())?.copy_from_slice(counts);
        Some(Self {
            len: u8::try_from(counts.len()).ok()?,
            entries,
        })
    }

    /// The counts, in the order given.
    #[must_use]
    pub fn as_slice(&self) -> &[SegmentAttachmentCount] {
        &self.entries[..usize::from(self.len)]
    }
}
