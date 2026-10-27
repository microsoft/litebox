// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, ProcessGroupRequest, ProcessGroupResponse,
};
use litebox_broker_protocol::process_group::{
    ProcessGroupError, ProcessGroupMembership, SetControllingTerminalRequest,
    SetForegroundGroupRequest, SetProcessGroupRequest,
};
use litebox_broker_protocol::{ObjectHandle, ProcessGroupId, ProcessId};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

type ProcessGroupResult<T> = core::result::Result<T, ProcessGroupError>;

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Moves process `process_id` into `process_group`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn set_process_group(
        &self,
        process_id: ProcessId,
        process_group: ProcessGroupId,
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

    /// Returns the foreground process group of the session that `terminal`
    /// controls and the session, given the caller's controlling terminal or a
    /// pseudo-terminal manager.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn get_foreground_group(
        &self,
        terminal: ObjectHandle,
    ) -> Result<ProcessGroupResult<ProcessGroupMembership>, Channel::Error> {
        match self.request_process_group(ProcessGroupRequest::GetForegroundGroup(terminal))? {
            ProcessGroupResponse::GetForegroundGroup(membership) => Ok(Ok(membership)),
            ProcessGroupResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected process group response: {response:?}"),
        }
    }

    /// Moves `process_group` of the caller's session into the foreground of
    /// its controlling terminal `terminal`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn set_foreground_group(
        &self,
        terminal: ObjectHandle,
        process_group: ProcessGroupId,
    ) -> Result<ProcessGroupResult<()>, Channel::Error> {
        let request = ProcessGroupRequest::SetForegroundGroup(SetForegroundGroupRequest {
            terminal,
            process_group,
        });
        match self.request_process_group(request)? {
            ProcessGroupResponse::SetForegroundGroup => Ok(Ok(())),
            ProcessGroupResponse::Failed(error) => Ok(Err(error)),
            response => panic!("broker returned unexpected process group response: {response:?}"),
        }
    }

    /// Makes `terminal`, or the subsidiary of pseudo-terminal manager
    /// `terminal`, the controlling terminal of the session that process
    /// `process_id` leads.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued process group request.
    pub fn set_controlling_terminal(
        &self,
        process_id: ProcessId,
        terminal: ObjectHandle,
    ) -> Result<ProcessGroupResult<()>, Channel::Error> {
        let request = ProcessGroupRequest::SetControllingTerminal(SetControllingTerminalRequest {
            process_id,
            terminal,
        });
        match self.request_process_group(request)? {
            ProcessGroupResponse::SetControllingTerminal => Ok(Ok(())),
            ProcessGroupResponse::Failed(error) => Ok(Err(error)),
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
