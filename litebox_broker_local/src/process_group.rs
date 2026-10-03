// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ProcessId;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ProcessGroupRequest, ProcessGroupResponse,
};
use litebox_broker_protocol::process_group::{ProcessGroupMembership, SetProcessGroupRequest};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Returns the group and session of process `process_id`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn process_group(
        &self,
        process_id: ProcessId,
    ) -> Result<ProcessGroupMembership, Channel::Error> {
        match self.request_process_group(ProcessGroupRequest::Get(process_id))? {
            ProcessGroupResponse::Get(membership) => Ok(membership),
            response => panic!("broker returned unexpected process group response: {response:?}"),
        }
    }

    /// Moves process `process_id` into `process_group`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn set_process_group(
        &self,
        process_id: ProcessId,
        process_group: ProcessId,
    ) -> Result<(), Channel::Error> {
        match self.request_process_group(ProcessGroupRequest::Set(SetProcessGroupRequest {
            process_id,
            process_group,
        }))? {
            ProcessGroupResponse::Set => Ok(()),
            response => panic!("broker returned unexpected process group response: {response:?}"),
        }
    }

    /// Makes process `process_id` the leader of a new session and of a new
    /// process group in it.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn create_session(&self, process_id: ProcessId) -> Result<(), Channel::Error> {
        match self.request_process_group(ProcessGroupRequest::CreateSession(process_id))? {
            ProcessGroupResponse::CreateSession => Ok(()),
            response => panic!("broker returned unexpected process group response: {response:?}"),
        }
    }

    fn request_process_group(
        &self,
        request: ProcessGroupRequest,
    ) -> Result<ProcessGroupResponse, Channel::Error> {
        match self.request(BrokerOperation::ProcessGroup(request))? {
            BrokerResult::ProcessGroup(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected process group response: {response:?}");
            }
        }
    }
}
