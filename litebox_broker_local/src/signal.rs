// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SignalRequest, SignalResponse,
};
use litebox_broker_protocol::signal::{PendingSignal, SendSignalRequest, TakeSignalRequest};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Opens this process's signals, returning a handle that becomes readable
    /// while any is pending.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued signal request.
    pub fn open_signals(&self) -> Result<ObjectHandle, Channel::Error> {
        match self.request_signal(SignalRequest::Open)? {
            SignalResponse::Open(response) => Ok(response.handle),
            response => panic!("broker returned unexpected signal response: {response:?}"),
        }
    }

    /// Sends `signal` to process `process_id`, or only checks that it exists
    /// if `signal` is zero.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued signal request.
    pub fn send_signal(&self, process_id: ProcessId, signal: u32) -> Result<(), Channel::Error> {
        match self.request_signal(SignalRequest::Send(SendSignalRequest {
            process_id,
            signal,
        }))? {
            SignalResponse::Sent => Ok(()),
            response => panic!("broker returned unexpected signal response: {response:?}"),
        }
    }

    /// Takes this process's lowest-numbered pending signal.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued signal request.
    pub fn take_signal(&self, handle: ObjectHandle) -> Result<PendingSignal, Channel::Error> {
        match self.request_signal(SignalRequest::Take(TakeSignalRequest { handle }))? {
            SignalResponse::Take(signal) => Ok(signal),
            response => panic!("broker returned unexpected signal response: {response:?}"),
        }
    }

    fn request_signal(&self, request: SignalRequest) -> Result<SignalResponse, Channel::Error> {
        match self.request(BrokerOperation::Signal(request))? {
            BrokerResult::Signal(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected signal response: {response:?}");
            }
        }
    }
}
