// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::fs::FileError;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SegmentRequest, SegmentResponse,
};
use litebox_broker_protocol::segment::{
    GetSegmentRequest, PrepareSegmentAttachRequest, PreparedSegmentAttach, SegmentAttachId,
    SegmentStatus, SetSegmentAttachmentsRequest, SetSegmentRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

/// The outcome of a segment operation: its result, or a guest-visible error.
type SegmentResult<T> = core::result::Result<T, FileError>;

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
    ) -> Result<SegmentResult<u32>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Get(request))?,
            SegmentResponse::Get(id) => id
        )
    }

    /// Reads a segment's metadata.
    pub fn segment_status(&self, id: u32) -> Result<SegmentResult<SegmentStatus>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Status(id))?,
            SegmentResponse::Status(status) => status
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
    pub fn remove_segment(&self, id: u32) -> Result<SegmentResult<()>, Channel::Error> {
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

    /// Records a reserved attachment once its backing object is mapped.
    pub fn confirm_segment_attach(
        &self,
        attachment: SegmentAttachId,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::ConfirmAttach(attachment))?,
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

    /// Replaces this process's attachment count of a segment.
    pub fn set_segment_attachments(
        &self,
        request: SetSegmentAttachmentsRequest,
    ) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::SetAttachments(request))?,
            SegmentResponse::SetAttachments => ()
        )
    }

    /// Copies this process's attachments to its pending child `target`.
    pub fn inherit_segments(&self, target: ProcessId) -> Result<SegmentResult<()>, Channel::Error> {
        expect_segment_response!(
            self.request_segment(SegmentRequest::Inherit(target))?,
            SegmentResponse::Inherit => ()
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
