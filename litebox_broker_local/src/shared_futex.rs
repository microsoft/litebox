// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SharedFutexRequest, SharedFutexResponse,
};
use litebox_broker_protocol::shared_futex::{
    FutexArmRequest, FutexDisarmRequest, FutexWakeRequest, SharedFutexKey, SharedMemoryId,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Reserves a block of shared memory IDs for this process to name memory it creates,
    /// returning the block's first ID, as
    /// [`ReserveMemoryIdsResponse`](litebox_broker_protocol::shared_futex::ReserveMemoryIdsResponse)
    /// describes.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared futex request.
    pub fn reserve_shared_memory_ids(&self) -> Result<SharedMemoryId, Channel::Error> {
        match self.request_shared_futex(SharedFutexRequest::ReserveMemoryIds)? {
            SharedFutexResponse::ReserveMemoryIds(response) => Ok(response.first),
            response => panic!("broker returned unexpected shared futex response: {response:?}"),
        }
    }

    /// Creates an idle futex waiter.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared futex request.
    pub fn create_futex_waiter(&self) -> Result<ObjectHandle, Channel::Error> {
        match self.request_shared_futex(SharedFutexRequest::CreateWaiter)? {
            SharedFutexResponse::CreateWaiter(response) => Ok(response.handle),
            response => panic!("broker returned unexpected shared futex response: {response:?}"),
        }
    }

    /// Arms the idle futex waiter `waiter` on the futex word `key`, to be selected by wakes whose
    /// masks intersect `bitset`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared futex request.
    pub fn futex_arm(
        &self,
        key: SharedFutexKey,
        bitset: u32,
        waiter: ObjectHandle,
    ) -> Result<(), Channel::Error> {
        let request = FutexArmRequest {
            key,
            bitset,
            waiter,
        };
        match self.request_shared_futex(SharedFutexRequest::Arm(request))? {
            SharedFutexResponse::Arm => Ok(()),
            response => panic!("broker returned unexpected shared futex response: {response:?}"),
        }
    }

    /// Wakes up to `count` waiters on the futex word `key` whose masks intersect `bitset`,
    /// returning how many it woke.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared futex request.
    pub fn futex_wake(
        &self,
        key: SharedFutexKey,
        count: u32,
        bitset: u32,
    ) -> Result<u32, Channel::Error> {
        let request = FutexWakeRequest { key, count, bitset };
        match self.request_shared_futex(SharedFutexRequest::Wake(request))? {
            SharedFutexResponse::Wake(response) => Ok(response.woken),
            response => panic!("broker returned unexpected shared futex response: {response:?}"),
        }
    }

    /// Disarms a futex waiter, returning whether a wake selected it since it was armed.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared futex request.
    pub fn futex_disarm(&self, waiter: ObjectHandle) -> Result<bool, Channel::Error> {
        match self
            .request_shared_futex(SharedFutexRequest::Disarm(FutexDisarmRequest { waiter }))?
        {
            SharedFutexResponse::Disarm(response) => Ok(response.woken),
            response => panic!("broker returned unexpected shared futex response: {response:?}"),
        }
    }

    fn request_shared_futex(
        &self,
        request: SharedFutexRequest,
    ) -> Result<SharedFutexResponse, Channel::Error> {
        match self.request(BrokerOperation::SharedFutex(request))? {
            BrokerResult::SharedFutex(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected shared futex response: {response:?}");
            }
        }
    }
}
