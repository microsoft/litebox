// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared-memory segments.

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
use crate::broker::{SegmentControl, SegmentControlResult};
use crate::sync::RawSyncPrimitivesProvider;
use alloc::sync::Arc;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::segment::{
    GetSegmentRequest, SegmentError as BrokerSegmentError, SegmentId, SegmentInfo,
    SegmentSlotStatus, SegmentSlotStatusRequest, SegmentStatus, SetSegmentRequest,
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
    #[error("invalid segment ID or size")]
    Invalid,
    #[error("insufficient access rights")]
    AccessDenied,
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
            // The association may not use segments.
            BrokerControlError::Broker(ErrorCode::PolicyDenied) => Self::AccessDenied,
            BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => Self::Unavailable,
            _ => Self::ServiceFailed,
        }
    }
}

fn segment_result<T>(result: SegmentControlResult<T>) -> Result<T, SegmentError> {
    Ok(result??)
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
    /// enumerates this process's namespace.
    pub fn segment_slot_status(&self, slot: u32) -> Result<SegmentSlotStatus, SegmentError> {
        segment_result(
            self.segment_broker()?
                .segment_slot_status(SegmentSlotStatusRequest { slot }),
        )
    }

    /// Summarizes this process's namespace and the segment limits that apply to it.
    pub fn segment_info(&self) -> Result<SegmentInfo, SegmentError> {
        segment_result(self.segment_broker()?.segment_info())
    }

    /// Changes the segment's permission bits.
    pub fn set_segment(&self, request: SetSegmentRequest) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.set_segment(request))
    }

    /// Unpublishes the segment's key; existing attachments keep it alive.
    pub fn remove_segment(&self, id: SegmentId) -> Result<(), SegmentError> {
        segment_result(self.segment_broker()?.remove_segment(id))
    }
}
