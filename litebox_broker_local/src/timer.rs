// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, TimerRequest, TimerResponse,
};
use litebox_broker_protocol::readiness::ReadinessFlags;
use litebox_broker_protocol::timer::{
    CreateTimerRequest, GetTimerRequest, ReadTimerRequest, SetTimerRequest, TimerSpec,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned timerfd for the given clock.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn create_timer(&self, clock_id: i32) -> Result<ObjectHandle, Channel::Error> {
        let response = self.request_timer(TimerRequest::Create(CreateTimerRequest { clock_id }))?;
        let TimerResponse::Create(response) = response else {
            panic!("broker returned unexpected timerfd create response: {response:?}");
        };
        Ok(response.handle)
    }

    /// Arms or disarms a broker-owned timerfd, returning the previous setting.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn set_timer(
        &self,
        handle: ObjectHandle,
        specification: TimerSpec,
        flags: u32,
    ) -> Result<(TimerSpec, ReadinessFlags), Channel::Error> {
        let response = self.request_timer(TimerRequest::Set(SetTimerRequest {
            handle,
            specification,
            flags,
        }))?;
        let TimerResponse::Set(response) = response else {
            panic!("broker returned unexpected timerfd set response: {response:?}");
        };
        Ok((response.previous, response.readiness))
    }

    /// Reads a broker-owned timerfd's current setting.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn get_timer(&self, handle: ObjectHandle) -> Result<TimerSpec, Channel::Error> {
        let response = self.request_timer(TimerRequest::Get(GetTimerRequest { handle }))?;
        let TimerResponse::Get(response) = response else {
            panic!("broker returned unexpected timerfd get response: {response:?}");
        };
        Ok(response.current)
    }

    /// Drains a broker-owned timerfd's accumulated expiration count.
    ///
    /// # Panics
    ///
    /// Panics if the broker returns a response for a different operation.
    pub fn read_timer(
        &self,
        handle: ObjectHandle,
    ) -> Result<(u64, bool, ReadinessFlags), Channel::Error> {
        let response = self.request_timer(TimerRequest::Read(ReadTimerRequest { handle }))?;
        let TimerResponse::Read(response) = response else {
            panic!("broker returned unexpected timerfd read response: {response:?}");
        };
        Ok((response.expirations, response.cancelled, response.readiness))
    }

    fn request_timer(&self, request: TimerRequest) -> Result<TimerResponse, Channel::Error> {
        match self.request(BrokerOperation::Timer(request))? {
            BrokerResult::Timer(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResult::ObjectClosed
            | BrokerResult::Readiness(_)
            | BrokerResult::Event(_)
            | BrokerResult::Pipe(_)
            | BrokerResult::Socket(_)) => {
                panic!("broker returned unexpected timerfd response: {response:?}");
            }
        }
    }
}
