// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed, process-shared memory segments. Segments record no owning identity,
//! and requests carry none.

use thiserror::Error;

/// The page size that segment lengths and byte totals are in.
pub const SEGMENT_PAGE_SIZE: u64 = 4096;

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
        #[error("invalid segment ID or size")]
        InvalidArgument,
        #[error("insufficient access rights")]
        AccessDenied,
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
        /// Whether the segment was removed and waits for its last attachment to end.
        pub removed: bool,
    }
}

wire_struct! {
    /// Looks up a key in the caller's namespace, optionally creating a segment.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct GetSegmentRequest {
        /// The key to look up, or zero to always create a private segment.
        pub key: i32,
        /// Byte length of a new segment; an existing one must be at least this long.
        pub size: u64,
        /// Permission bits of a new segment.
        pub mode: u16,
        /// Create a segment if the key has none.
        pub create: bool,
        /// With `create`, fail if the key already has a segment.
        pub exclusive: bool,
    }
}

wire_struct! {
    /// Changes a segment's permission bits.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SetSegmentRequest {
        /// The segment.
        pub id: SegmentId,
        /// The new permission bits.
        pub mode: u16,
    }
}

wire_struct! {
    /// The caller's namespace and the segment limits that apply to the caller.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SegmentInfo {
        /// Live segments in the namespace, including removed ones still attached.
        pub segments: u32,
        /// Page-rounded bytes of those segments.
        pub bytes: u64,
        /// The namespace's highest occupied slot, if any segment lives in it.
        pub highest_slot: Option<u32>,
        /// Largest byte length of one segment.
        pub max_segment_size: u64,
        /// How many segments may exist at once.
        pub max_segments: u32,
        /// Largest total of page-rounded bytes of segments.
        pub max_total_bytes: u64,
    }
}

wire_struct! {
    /// Reads the metadata of the segment in a slot of the caller's namespace.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SegmentSlotStatusRequest {
        /// The slot, a small index that enumerates the namespace's segments.
        pub slot: u32,
    }
}

wire_struct! {
    /// The segment in a slot, and its metadata.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SegmentSlotStatus {
        /// The segment.
        pub id: SegmentId,
        /// Its metadata.
        pub status: SegmentStatus,
    }
}
