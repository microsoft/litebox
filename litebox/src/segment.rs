// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared-memory segments.

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
use crate::broker::{SegmentControl, SegmentControlResult};
use crate::fs::SharedFileObject;
use crate::platform::SharedObjectProvider;
use crate::platform::page_mgmt::SharedObjectReceiveError;
use crate::sync::RawSyncPrimitivesProvider;
use alloc::sync::Arc;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::segment::{
    ConfirmSegmentAttachRequest, GetSegmentRequest, PrepareSegmentAttachRequest, SegmentAttachId,
    SegmentAttachmentCount, SegmentAttachmentCounts, SegmentError as BrokerSegmentError, SegmentId,
    SegmentInfo, SegmentSlotStatus, SegmentSlotStatusRequest, SegmentStatus, SetSegmentRequest,
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

impl From<BrokerSegmentError> for SegmentError {
    fn from(error: BrokerSegmentError) -> Self {
        match error {
            BrokerSegmentError::Unavailable => Self::Unavailable,
            BrokerSegmentError::Exists => Self::Exists,
            BrokerSegmentError::Missing => Self::Missing,
            BrokerSegmentError::InvalidArgument => Self::Invalid,
            BrokerSegmentError::AccessDenied => Self::AccessDenied,
            BrokerSegmentError::NotOwner => Self::NotOwner,
            BrokerSegmentError::NoSpace => Self::NoSpace,
            BrokerSegmentError::Io => Self::Io,
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
    pub reservation: AttachReservation,
}

/// A reserved attachment, which pins the segment without counting as an
/// attachment. Dropping it cancels the reservation.
pub struct AttachReservation {
    broker: Arc<dyn SegmentControl>,
    attachment: Option<SegmentAttachId>,
}

impl AttachReservation {
    /// Records the attachment, once its backing object is mapped, with `count`
    /// as this process's total for the segment, this attachment included. On
    /// failure, the reservation is cancelled.
    pub fn confirm(mut self, count: SegmentAttachmentCount) -> Result<(), SegmentError> {
        let attachment = self.attachment.take().ok_or(SegmentError::Invalid)?;
        let result = segment_result(
            self.broker
                .confirm_segment_attach(ConfirmSegmentAttachRequest { attachment, count }),
        );
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
    fn segment_broker(&self) -> Result<Arc<dyn SegmentControl>, SegmentError> {
        let broker = self.broker_control().ok_or(SegmentError::Unavailable)?;
        Ok(broker)
    }

    /// Gets the ID of the segment with `request.key`, or creates a
    /// zero-filled one as `request` allows. Key 0 always creates.
    pub fn get_segment(&self, request: GetSegmentRequest) -> Result<SegmentId, SegmentError> {
        segment_result(self.segment_broker()?.get_segment(request))
    }

    /// Reads the segment's metadata.
    pub fn segment_status(&self, id: SegmentId) -> Result<SegmentStatus, SegmentError> {
        segment_result(self.segment_broker()?.segment_status(id))
    }

    /// Reads the metadata of the segment in `slot`, a small index that
    /// enumerates this process's namespace, requiring read permission if
    /// `require_read` is set.
    pub fn segment_slot_status(
        &self,
        slot: u32,
        require_read: bool,
    ) -> Result<SegmentSlotStatus, SegmentError> {
        segment_result(
            self.segment_broker()?
                .segment_slot_status(SegmentSlotStatusRequest { slot, require_read }),
        )
    }

    /// Summarizes this process's namespace and the segment limits that apply to it.
    pub fn segment_info(&self) -> Result<SegmentInfo, SegmentError> {
        segment_result(self.segment_broker()?.segment_info())
    }

    /// Changes the segment's owner and permission bits.
    pub fn set_segment(&self, request: SetSegmentRequest) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.set_segment(request))
    }

    /// Unpublishes the segment's key; existing attachments keep it alive.
    pub fn remove_segment(&self, id: SegmentId) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.remove_segment(id))
    }

    /// Reserves an attachment of `request.id` and takes its backing object
    /// from `platform`.
    pub fn prepare_segment_attach<Provider: SharedObjectProvider<ALIGN>, const ALIGN: usize>(
        &self,
        platform: &Provider,
        request: PrepareSegmentAttachRequest,
    ) -> Result<PreparedAttach<Provider::SharedObject>, SegmentError> {
        let broker = self.segment_broker()?;
        let prepared = segment_result(broker.prepare_segment_attach(request))?;
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

    /// Replaces this process's attachment count of each segment in `counts`, as
    /// splitting or releasing its mapped areas changed them. Each count is
    /// replaced even if another fails; this returns the first failure. Each
    /// later change publishes the full count, so it also makes up for an
    /// earlier failed one.
    pub fn set_segment_attachments(
        &self,
        counts: &[SegmentAttachmentCount],
    ) -> Result<(), SegmentError> {
        let broker = self.segment_broker()?;
        let mut first_error = None;
        let batches = counts
            .chunks(SegmentAttachmentCounts::CAPACITY)
            .filter_map(SegmentAttachmentCounts::new);
        for batch in batches {
            if let Err(error) = segment_result(broker.set_segment_attachments(batch)) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// Refuses confirmations, and records which attachment it cancelled.
    #[derive(Default)]
    struct RefusingBroker {
        cancelled: AtomicU64,
    }

    impl SegmentControl for RefusingBroker {
        fn get_segment(&self, _: GetSegmentRequest) -> SegmentControlResult<SegmentId> {
            unreachable!()
        }
        fn segment_status(&self, _: SegmentId) -> SegmentControlResult<SegmentStatus> {
            unreachable!()
        }
        fn segment_slot_status(
            &self,
            _: SegmentSlotStatusRequest,
        ) -> SegmentControlResult<SegmentSlotStatus> {
            unreachable!()
        }
        fn segment_info(&self) -> SegmentControlResult<SegmentInfo> {
            unreachable!()
        }
        fn set_segment(&self, _: SetSegmentRequest) -> SegmentControlResult<()> {
            unreachable!()
        }
        fn remove_segment(&self, _: SegmentId) -> SegmentControlResult<()> {
            unreachable!()
        }
        fn prepare_segment_attach(
            &self,
            _: PrepareSegmentAttachRequest,
        ) -> SegmentControlResult<litebox_broker_protocol::segment::PreparedSegmentAttach> {
            unreachable!()
        }
        fn confirm_segment_attach(
            &self,
            _: ConfirmSegmentAttachRequest,
        ) -> SegmentControlResult<()> {
            Ok(Err(BrokerSegmentError::InvalidArgument))
        }
        fn cancel_segment_attach(&self, attachment: SegmentAttachId) -> SegmentControlResult<()> {
            self.cancelled.store(attachment.0, Ordering::Relaxed);
            Ok(Ok(()))
        }
        fn set_segment_attachments(&self, _: SegmentAttachmentCounts) -> SegmentControlResult<()> {
            unreachable!()
        }
    }

    #[test]
    fn a_refused_confirmation_cancels_the_reservation() {
        let broker = Arc::new(RefusingBroker::default());
        let reservation = AttachReservation {
            broker: broker.clone(),
            attachment: Some(SegmentAttachId(9)),
        };
        let count = SegmentAttachmentCount {
            id: SegmentId(1),
            count: 1,
            generation: 1,
        };
        assert_eq!(reservation.confirm(count), Err(SegmentError::Invalid));
        assert_eq!(broker.cancelled.load(Ordering::Relaxed), 9);
    }
}
