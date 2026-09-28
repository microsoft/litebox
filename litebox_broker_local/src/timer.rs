// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, TimerRequest, TimerResponse,
};
use litebox_broker_protocol::timer::{
    GetTimerRequest, ReadTimerRequest, SetTimerRequest, TimerSpec,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a disarmed broker-owned timer.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn create_timer(&self) -> Result<ObjectHandle, Channel::Error> {
        match self.request_timer(TimerRequest::Create)? {
            TimerResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected timer response: {response:?}"),
        }
    }

    /// Arms or disarms a broker-owned timer, returning its previous schedule.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn set_timer(
        &self,
        handle: ObjectHandle,
        spec: TimerSpec,
    ) -> Result<TimerSpec, Channel::Error> {
        match self.request_timer(TimerRequest::Set(SetTimerRequest { handle, spec }))? {
            TimerResponse::Set(response) => Ok(response.previous),
            response => panic!("broker returned unexpected timer response: {response:?}"),
        }
    }

    /// Returns a broker-owned timer's current schedule.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn get_timer(&self, handle: ObjectHandle) -> Result<TimerSpec, Channel::Error> {
        match self.request_timer(TimerRequest::Get(GetTimerRequest { handle }))? {
            TimerResponse::Get(response) => Ok(response.current),
            response => panic!("broker returned unexpected timer response: {response:?}"),
        }
    }

    /// Consumes a broker-owned timer's pending expirations.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued timer request.
    pub fn read_timer(&self, handle: ObjectHandle) -> Result<u64, Channel::Error> {
        match self.request_timer(TimerRequest::Read(ReadTimerRequest { handle }))? {
            TimerResponse::Read(response) => Ok(response.expirations),
            response => panic!("broker returned unexpected timer response: {response:?}"),
        }
    }

    fn request_timer(&self, request: TimerRequest) -> Result<TimerResponse, Channel::Error> {
        match self.request(BrokerOperation::Timer(request))? {
            BrokerResult::Timer(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected timer response: {response:?}");
            }
        }
    }
}
