// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared-memory segments, independent of file descriptors and paths.

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
use crate::broker::{BrokerControl, SegmentControlResult};
use crate::fs::SharedFileObject;
use crate::platform::SharedObjectProvider;
use crate::platform::page_mgmt::SharedObjectReceiveError;
use crate::sync::RawSyncPrimitivesProvider;
use alloc::sync::Arc;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::segment::{
    GetSegmentRequest, PrepareSegmentAttachRequest, SegmentAttachId, SegmentStatus,
    SetSegmentAttachmentsRequest, SetSegmentRequest,
};
use litebox_platform::time::TimeProvider;

/// Failure accessing a shared segment.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SegmentError {
    #[error("shared segments unavailable")]
    Unavailable,
    #[error("shared segment key already in use")]
    Exists,
    #[error("no segment has this key")]
    Missing,
    #[error("invalid segment ID, size or attachment")]
    Invalid,
    #[error("insufficient access rights")]
    AccessDenied,
    #[error("not the segment owner")]
    NotOwner,
    #[error("shared segment capacity exhausted")]
    NoSpace,
    #[error("insufficient memory")]
    NoMemory,
    #[error("shared segment I/O failed")]
    Io,
    #[error("segment service failed")]
    ServiceFailed,
}

impl From<FileError> for SegmentError {
    fn from(error: FileError) -> Self {
        match error {
            FileError::AlreadyExists => Self::Exists,
            FileError::NoSuchFileOrDirectory => Self::Missing,
            FileError::InvalidArgument => Self::Invalid,
            FileError::AccessNotAllowed => Self::AccessDenied,
            FileError::NotOwner => Self::NotOwner,
            FileError::NoSpace => Self::NoSpace,
            FileError::Io => Self::Io,
            FileError::NoSuchDevice | FileError::NotSupported => Self::Unavailable,
            _ => Self::ServiceFailed,
        }
    }
}

impl From<BrokerControlError> for SegmentError {
    fn from(error: BrokerControlError) -> Self {
        match error {
            BrokerControlError::Broker(ErrorCode::OutOfMemory) => Self::NoMemory,
            BrokerControlError::Broker(ErrorCode::ResourceExhausted) => Self::NoSpace,
            // The association may not use segments, like a principal without access.
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::AccessDenied,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            _ => Self::ServiceFailed,
        }
    }
}

impl From<SharedObjectReceiveError> for SegmentError {
    fn from(error: SharedObjectReceiveError) -> Self {
        match error {
            SharedObjectReceiveError::UnsupportedByPlatform => Self::Unavailable,
            SharedObjectReceiveError::OutOfMemory => Self::NoMemory,
            SharedObjectReceiveError::Io => Self::Io,
        }
    }
}

fn segment_result<T>(result: SegmentControlResult<T>) -> Result<T, SegmentError> {
    Ok(result??)
}

/// A segment's backing object, delivered for an attachment that is not
/// recorded until confirmed.
pub struct PreparedAttach<Object> {
    /// The backing object, covering the page-rounded segment.
    pub object: SharedFileObject<Object>,
    /// The segment's byte length, before rounding to pages.
    pub size: u64,
    /// Confirms the attachment or, if dropped first, cancels it.
    pub reservation: AttachReservation,
}

/// A reserved attachment, which pins the segment without counting as an
/// attachment. Dropping it cancels the reservation.
pub struct AttachReservation {
    broker: Arc<dyn BrokerControl>,
    attachment: Option<SegmentAttachId>,
}

impl AttachReservation {
    /// Records the attachment, once its backing object is mapped. On failure,
    /// the reservation is cancelled.
    pub fn confirm(mut self) -> Result<(), SegmentError> {
        let attachment = self.attachment.take().ok_or(SegmentError::Invalid)?;
        let result = segment_result(self.broker.confirm_segment_attach(attachment));
        if result.is_err() {
            self.attachment = Some(attachment);
        }
        result
    }
}

impl Drop for AttachReservation {
    fn drop(&mut self) {
        if let Some(attachment) = self.attachment.take()
            && let Err(error) = segment_result(self.broker.cancel_segment_attach(attachment))
        {
            // The broker releases the reservation when this process ends.
            litebox_util_log::warn!(error:?; "failed to cancel a segment attach");
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    fn segment_broker(&self) -> Result<Arc<dyn BrokerControl>, SegmentError> {
        self.broker_control().ok_or(SegmentError::Unavailable)
    }

    /// Gets the ID of the segment with `request.key`, or creates a
    /// zero-filled one as `request` allows. Key 0 always creates.
    pub fn get_segment(&self, request: GetSegmentRequest) -> Result<u32, SegmentError> {
        segment_result(self.segment_broker()?.get_segment(request))
    }

    /// Reads the segment's metadata.
    pub fn segment_status(&self, id: u32) -> Result<SegmentStatus, SegmentError> {
        segment_result(self.segment_broker()?.segment_status(id))
    }

    /// Changes the segment's owner and permission bits.
    pub fn set_segment(&self, request: SetSegmentRequest) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.set_segment(request))
    }

    /// Unpublishes the segment's key; existing attachments keep it alive.
    pub fn remove_segment(&self, id: u32) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.remove_segment(id))
    }

    /// Reserves an attachment of segment `id` and takes its backing object
    /// from `platform`.
    pub fn prepare_segment_attach<Provider: SharedObjectProvider<ALIGN>, const ALIGN: usize>(
        &self,
        platform: &Provider,
        id: u32,
        writable: bool,
    ) -> Result<PreparedAttach<Provider::SharedObject>, SegmentError> {
        let broker = self.segment_broker()?;
        let prepared = segment_result(
            broker.prepare_segment_attach(PrepareSegmentAttachRequest { id, writable }),
        )?;
        let reservation = AttachReservation {
            broker,
            attachment: Some(prepared.attachment),
        };
        // SAFETY: The broker delivered this handle to this process before answering; it is
        // taken only here.
        let object = unsafe { SharedFileObject::take(platform, prepared.mapping) }?;
        Ok(PreparedAttach {
            object,
            size: prepared.size,
            reservation,
        })
    }

    /// Replaces this process's attachment count of segment `id`, as splitting
    /// or releasing its mapped areas changed it. Each later change publishes
    /// the full count, so it also makes up for an earlier failed one.
    pub fn set_segment_attachments(&self, id: u32, count: u64) -> Result<(), SegmentError> {
        segment_result(
            self.segment_broker()?
                .set_segment_attachments(SetSegmentAttachmentsRequest { id, count }),
        )
    }

    /// Copies this process's attachments to pending child `target`, which
    /// inherits its address space.
    pub fn inherit_segments(&self, target: ProcessId) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.inherit_segments(target))
    }
}
