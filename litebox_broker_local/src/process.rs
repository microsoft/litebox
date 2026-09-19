// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::message::{BrokerOperation, BrokerResult};
use litebox_broker_protocol::process::{
    InheritedProcessObjects, MAX_PROCESS_BOOTSTRAP_SIZE, ProcessBootstrapFormat,
    ProcessBootstrapVersion, ProcessStartupDescriptor, StartedProcess,
};
use litebox_broker_protocol::shared_buffer::SharedBufferSequence;
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Requests materialization of one child process.
    ///
    /// This call blocks until the child's broker association is active or
    /// launch fails. The caller must retain exclusive ownership of the
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
        match self.request(BrokerOperation::StartProcess(ProcessStartupDescriptor {
            format,
            version,
            buffer,
            inherited_objects,
        }))? {
            BrokerResult::ProcessStarted(started) => Ok(started),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => panic!("broker returned unexpected process-start response: {response:?}"),
        }
    }
}
