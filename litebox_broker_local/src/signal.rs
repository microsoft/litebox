// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SignalRequest, SignalResponse,
};
use litebox_broker_protocol::signal::{
    SendSignalRequest, SignalEvent, SignalTarget, TakeSignalRequest,
};
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

    /// Sends `signal` to the processes `target` selects, or only checks that
    /// one exists if `signal` is zero.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued signal request.
    pub fn send_signal(&self, target: SignalTarget, signal: u32) -> Result<(), Channel::Error> {
        match self.request_signal(SignalRequest::Send(SendSignalRequest { target, signal }))? {
            SignalResponse::Sent => Ok(()),
            response => panic!("broker returned unexpected signal response: {response:?}"),
        }
    }

    /// Takes this process's lowest-numbered pending signal, or else its
    /// pending child exit.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued signal request.
    pub fn take_signal(&self, handle: ObjectHandle) -> Result<SignalEvent, Channel::Error> {
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
