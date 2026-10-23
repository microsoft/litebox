// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::message::{
    BrokerOperation, BrokerResult, SharedMemoryRequest, SharedMemoryResponse,
};
use litebox_broker_protocol::shared_memory::{
    CreateSharedMemoryRequest, FutexArmRequest, FutexDisarmRequest, FutexWakeRequest,
};
use litebox_broker_transport::channel::LocalCallChannel;

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalCallChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned shared memory object of `length` bytes.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared memory request.
    pub fn create_shared_memory(&self, length: u64) -> Result<ObjectHandle, Channel::Error> {
        match self.request_shared_memory(SharedMemoryRequest::Create(
            CreateSharedMemoryRequest { length },
        ))? {
            SharedMemoryResponse::Create(response) => Ok(response.handle),
            response => panic!("broker returned unexpected shared memory response: {response:?}"),
        }
    }

    /// Creates an idle futex waiter for the calling thread.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared memory request.
    pub fn create_futex_waiter(&self) -> Result<ObjectHandle, Channel::Error> {
        match self.request_shared_memory(SharedMemoryRequest::CreateFutexWaiter)? {
            SharedMemoryResponse::CreateFutexWaiter(response) => Ok(response.handle),
            response => panic!("broker returned unexpected shared memory response: {response:?}"),
        }
    }

    /// Arms the idle futex waiter `waiter` on the futex word at `offset` of shared memory
    /// `memory`, to be selected by wakes whose masks intersect `bitset`.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared memory request.
    pub fn futex_arm(
        &self,
        memory: ObjectHandle,
        offset: u64,
        bitset: u32,
        waiter: ObjectHandle,
    ) -> Result<(), Channel::Error> {
        let request = FutexArmRequest {
            memory,
            offset,
            bitset,
            waiter,
        };
        match self.request_shared_memory(SharedMemoryRequest::FutexArm(request))? {
            SharedMemoryResponse::FutexArm => Ok(()),
            response => panic!("broker returned unexpected shared memory response: {response:?}"),
        }
    }

    /// Wakes up to `count` waiters on the futex word at `offset` of shared memory `memory` whose
    /// masks intersect `bitset`, returning how many it woke.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared memory request.
    pub fn futex_wake(
        &self,
        memory: ObjectHandle,
        offset: u64,
        count: u32,
        bitset: u32,
    ) -> Result<u32, Channel::Error> {
        let request = FutexWakeRequest {
            memory,
            offset,
            count,
            bitset,
        };
        match self.request_shared_memory(SharedMemoryRequest::FutexWake(request))? {
            SharedMemoryResponse::FutexWake(response) => Ok(response.woken),
            response => panic!("broker returned unexpected shared memory response: {response:?}"),
        }
    }

    /// Disarms a futex waiter, returning whether a wake selected it since it was armed.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a protocol
    /// response that does not match the issued shared memory request.
    pub fn futex_disarm(&self, waiter: ObjectHandle) -> Result<bool, Channel::Error> {
        match self.request_shared_memory(SharedMemoryRequest::FutexDisarm(FutexDisarmRequest {
            waiter,
        }))? {
            SharedMemoryResponse::FutexDisarm(response) => Ok(response.woken),
            response => panic!("broker returned unexpected shared memory response: {response:?}"),
        }
    }

    fn request_shared_memory(
        &self,
        request: SharedMemoryRequest,
    ) -> Result<SharedMemoryResponse, Channel::Error> {
        match self.request(BrokerOperation::SharedMemory(request))? {
            BrokerResult::SharedMemory(response) => Ok(response),
            BrokerResult::Error(error) => Err(BrokerLocalError::Broker(error)),
            response => {
                panic!("broker returned unexpected shared memory response: {response:?}");
            }
        }
    }
}
