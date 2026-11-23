// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SegmentRequest, SegmentResponse,
};
use litebox_broker_protocol::segment::{
    ConfirmSegmentAttachRequest, GetSegmentRequest, PrepareSegmentAttachRequest,
    PreparedSegmentAttach, SegmentAttachId, SegmentAttachmentCounts, SegmentError, SegmentId,
    SegmentInfo, SegmentSlotStatus, SegmentSlotStatusRequest, SegmentStatus, SetSegmentRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

/// The outcome of a segment operation: its result, or a guest-visible error.
type SegmentResult<T> = core::result::Result<T, SegmentError>;

/// Matches `$response` against the response pattern for its request, or panics.
macro_rules! expect_segment_response {
    ($response:expr, $pattern:pat => $value:expr) => {
        match $response {
            $pattern => Ok(Ok($value)),
            SegmentResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected segment response: {response:?}"),
        }
    };
}

/// Keyed shared segments. Each method panics if the broker returns a response
/// for another operation.
impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Looks up a key, optionally creating a segment, and returns its ID.
    pub fn get_segment(
        &self,
        request: GetSegmentRequest,
    ) -> Result<SegmentResult<SegmentId>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Get(request))?,
            SegmentResponse::Get(id) => id
        )
    }

    /// Reads a segment's metadata.
    pub fn segment_status(
        &self,
        id: SegmentId,
    ) -> Result<SegmentResult<SegmentStatus>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Status(id))?,
            SegmentResponse::Status(status) => status
        )
    }

    /// Reads the metadata of the segment in a slot of this process's namespace.
    pub fn segment_slot_status(
        &self,
        request: SegmentSlotStatusRequest,
    ) -> Result<SegmentResult<SegmentSlotStatus>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::SlotStatus(request))?,
            SegmentResponse::SlotStatus(found) => found
        )
    }

    /// Summarizes this process's namespace and the segment limits that apply to it.
    pub fn segment_info(&self) -> Result<SegmentResult<SegmentInfo>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Info)?,
            SegmentResponse::Info(info) => info
        )
    }

    /// Changes a segment's owner and permission bits.
    pub fn set_segment(
        &self,
        request: SetSegmentRequest,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Set(request))?,
            SegmentResponse::Set => ()
        )
    }

    /// Unpublishes a segment's key, freeing it once no attachments remain.
    pub fn remove_segment(&self, id: SegmentId) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Remove(id))?,
            SegmentResponse::Remove => ()
        )
    }

    /// Reserves an attachment, whose backing object the broker delivers out
    /// of band under the returned token.
    pub fn prepare_segment_attach(
        &self,
        request: PrepareSegmentAttachRequest,
    ) -> Result<SegmentResult<PreparedSegmentAttach>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::PrepareAttach(request))?,
            SegmentResponse::PrepareAttach(prepared) => prepared
        )
    }

    /// Records a reserved attachment once its backing object is mapped,
    /// replacing this process's count of the segment.
    pub fn confirm_segment_attach(
        &self,
        request: ConfirmSegmentAttachRequest,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::ConfirmAttach(request))?,
            SegmentResponse::ConfirmAttach => ()
        )
    }

    /// Releases an unused reservation.
    pub fn cancel_segment_attach(
        &self,
        attachment: SegmentAttachId,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::CancelAttach(attachment))?,
            SegmentResponse::CancelAttach => ()
        )
    }

    /// Replaces this process's attachment counts of up to
    /// [`SegmentAttachmentCounts::CAPACITY`] segments, applying each even if
    /// another fails.
    pub fn set_segment_attachments(
        &self,
        counts: SegmentAttachmentCounts,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::SetAttachments(counts))?,
            SegmentResponse::SetAttachments => ()
        )
    }

    fn request_segment(&self, request: SegmentRequest) -> Result<SegmentResponse, Channel::Error> {
        match self.request(BrokerOperation::Segment(request))? {
            BrokerResult::Segment(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected segment response: {response:?}"),
        }
    }
}
