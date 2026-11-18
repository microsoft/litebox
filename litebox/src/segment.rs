// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Keyed shared-memory segments, independent of file descriptors and paths.

use crate::LiteBox;
use crate::broker::error::BrokerControlError;
use crate::fs::SharedFileObject;
use crate::platform::SharedObjectProvider;
use crate::platform::page_mgmt::SharedObjectReceiveError;
use crate::sync::RawSyncPrimitivesProvider;
use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fs::{FileError, FileUser};
use litebox_broker_protocol::segment::{
    SegmentAttachId, SegmentRequest, SegmentResponse, SegmentStatus,
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> LiteBox<Platform> {
    fn segment(&self, request: SegmentRequest) -> Result<SegmentResponse, SegmentError> {
        let control = self.broker_control().ok_or(SegmentError::Unavailable)?;
        match control.segment(request) {
            Ok(SegmentResponse::Failed(error)) => Err(match error {
                FileError::AlreadyExists => SegmentError::Exists,
                FileError::NoSuchFileOrDirectory => SegmentError::Missing,
                FileError::InvalidArgument => SegmentError::Invalid,
                FileError::AccessNotAllowed => SegmentError::AccessDenied,
                FileError::NotOwner => SegmentError::NotOwner,
                FileError::NoSpace => SegmentError::NoSpace,
                FileError::Io => SegmentError::Io,
                FileError::NoSuchDevice | FileError::NotSupported => SegmentError::Unavailable,
                _ => SegmentError::ServiceFailed,
            }),
            Ok(response) => Ok(response),
            Err(error) => Err(match error {
                BrokerControlError::Broker(ErrorCode::OutOfMemory) => SegmentError::NoMemory,
                BrokerControlError::Broker(ErrorCode::ResourceExhausted) => SegmentError::NoSpace,
                BrokerControlError::Broker(ErrorCode::PolicyDenied) => SegmentError::NotOwner,
                BrokerControlError::Broker(ErrorCode::UnsupportedOperation) => {
                    SegmentError::Unavailable
                }
                _ => SegmentError::ServiceFailed,
            }),
        }
    }

    fn segment_done(&self, request: SegmentRequest) -> Result<(), SegmentError> {
        match self.segment(request)? {
            SegmentResponse::Done => Ok(()),
            _ => Err(SegmentError::ServiceFailed),
        }
    }

    /// Gets the ID belonging to `key`, optionally creating a zero-filled segment.
    pub fn get_segment(
        &self,
        key: i32,
        size: u64,
        mode: u16,
        create: bool,
        exclusive: bool,
    ) -> Result<u32, SegmentError> {
        match self.segment(SegmentRequest::Get {
            key,
            size,
            mode,
            create,
            exclusive,
        })? {
            SegmentResponse::Id(id) => Ok(id),
            _ => Err(SegmentError::ServiceFailed),
        }
    }

    /// Reads the segment's metadata.
    pub fn segment_status(&self, id: u32) -> Result<SegmentStatus, SegmentError> {
        match self.segment(SegmentRequest::Status { id })? {
            SegmentResponse::Status(status) => Ok(status),
            _ => Err(SegmentError::ServiceFailed),
        }
    }

    /// Changes the segment's owner and permissions.
    pub fn set_segment(&self, id: u32, owner: FileUser, mode: u16) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::Set { id, owner, mode })
    }

    /// Removes the segment's key, but keeps existing attachments live.
    pub fn delete_segment(&self, id: u32) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::Delete { id })
    }

    /// Obtains backing memory for a provisional attachment.
    ///
    /// After mapping succeeds, call [`Self::confirm_segment_attach`]. If mapping
    /// fails, call [`Self::cancel_segment_attach`] instead. A reservation pins the
    /// backing memory but does not count as an attachment.
    pub fn attach_segment<Provider: SharedObjectProvider<ALIGN>, const ALIGN: usize>(
        &self,
        platform: &Provider,
        id: u32,
        writable: bool,
    ) -> Result<
        (
            SharedFileObject<Provider::SharedObject>,
            u64,
            SegmentAttachId,
        ),
        SegmentError,
    > {
        let SegmentResponse::AttachPrepared {
            attachment,
            mapping,
            size,
        } = self.segment(SegmentRequest::Attach { id, writable })?
        else {
            return Err(SegmentError::ServiceFailed);
        };
        // SAFETY: Attach delivered this handle to this process; it is consumed only here.
        match unsafe { platform.take_shared_object(mapping.token) } {
            Ok(object) => Ok((
                SharedFileObject {
                    object,
                    memory: mapping.memory,
                    may_write: mapping.writable && writable,
                },
                size,
                attachment,
            )),
            Err(error) => {
                if let Err(cancel) = self.cancel_segment_attach(attachment) {
                    litebox_util_log::warn!(id, cancel:?; "failed to cancel a segment attach");
                }
                Err(match error {
                    SharedObjectReceiveError::UnsupportedByPlatform => SegmentError::Unavailable,
                    SharedObjectReceiveError::OutOfMemory => SegmentError::NoMemory,
                    SharedObjectReceiveError::Io => SegmentError::Io,
                })
            }
        }
    }

    /// Records a successfully mapped attachment until [`Self::detach_segment`].
    pub fn confirm_segment_attach(&self, attachment: SegmentAttachId) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::ConfirmAttach { attachment })
    }

    /// Releases an unused provisional attachment without changing segment metadata.
    pub fn cancel_segment_attach(&self, attachment: SegmentAttachId) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::CancelAttach { attachment })
    }

    /// Releases an attachment, including one inherited by a child process.
    pub fn detach_segment(&self, id: u32) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::Detach { id })
    }

    /// Adjusts a confirmed attachment count when mapped regions split or are released.
    pub fn adjust_segment_attachments(&self, id: u32, delta: i64) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::AdjustAttachments { id, delta })
    }

    /// Copies this process's attachments to pending child `target`, which inherits its
    /// address space.
    pub fn inherit_segments(&self, target: ProcessId) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::Inherit { target })
    }

    /// Moves this process or its pending child to an empty namespace. Existing attachments live on.
    pub fn new_segment_namespace(&self, target: ProcessId) -> Result<(), SegmentError> {
        self.segment_done(SegmentRequest::NewNamespace { target })
    }
}
