// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ThreadId;
use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrap, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessReadyRequest, ProcessStartToken, StartProcessRequest,
    StartedProcess,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Requests materialization of one child process.
    ///
    /// The returned token must be acknowledged before the child may begin
    /// guest execution. The caller must retain exclusive ownership of the
    /// bootstrap sequence until this method returns.
    ///
    /// # Panics
    ///
    /// Panics if the bootstrap length differs from the shared-buffer sequence
    /// or the broker returns a response for another operation.
    pub fn request_process_start(
        &self,
        format: ProcessBootstrapFormat,
        version: ProcessBootstrapVersion,
        buffer: SharedBufferSequence,
        bootstrap: &[u8],
        inherited_objects: InheritedProcessObjects,
    ) -> Result<StartedProcess, Channel::Error> {
        if buffer.length() > MAX_PROCESS_BOOTSTRAP_SIZE {
            return Err(BrokerLocalError::Broker(ErrorCode::ResourceExhausted));
        }
        self.write_shared_buffer(buffer, bootstrap);
        match self.request(BrokerOperation::StartProcess(StartProcessRequest {
            bootstrap: ProcessBootstrap {
                format,
                version,
                buffer,
            },
            inherited_objects,
        }))? {
            BrokerResult::ProcessStarted(started) => Ok(started),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected process-start response: {response:?}"),
        }
    }

    /// Acknowledges a successful process-start result and releases the child.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn acknowledge_process_start(
        &self,
        token: ProcessStartToken,
    ) -> Result<(), Channel::Error> {
        match self.request(BrokerOperation::AcknowledgeProcessStart(token))? {
            BrokerResult::ProcessStartAcknowledged => Ok(()),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected process-start acknowledgement: {response:?}")
            }
        }
    }

    /// Reports that this prepared process is ready and waits for parent acknowledgement.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for another operation.
    pub fn process_ready(&self, initial_thread_id: Option<ThreadId>) -> Result<(), Channel::Error> {
        match self.request(BrokerOperation::ProcessReady(ProcessReadyRequest {
            initial_thread_id,
        }))? {
            BrokerResult::ProcessReady => Ok(()),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected process-ready response: {response:?}"),
        }
    }
}
