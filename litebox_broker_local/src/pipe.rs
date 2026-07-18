// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse, PipeRequest, PipeResponse};
use litebox_broker_protocol::pipe::{
    CreatePipeRequest, CreatePipeResponse, ReadPipeRequest, WritePipeRequest,
};

use crate::{BrokerLocal, BrokerLocalError, Result};

impl<Channel: LocalControlChannel> BrokerLocal<Channel> {
    /// Creates a broker-owned byte pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn create_pipe(
        &mut self,
        capacity: u64,
        atomic_write_size: u64,
    ) -> Result<CreatePipeResponse, Channel::Error> {
        match self.request_pipe(PipeRequest::Create(CreatePipeRequest {
            capacity,
            atomic_write_size,
        }))? {
            PipeResponse::Create(response) => Ok(response),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    /// Reads bytes from a broker-owned pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn read_pipe(
        &mut self,
        handle: ObjectHandle,
        length: u32,
    ) -> Result<Vec<u8>, Channel::Error> {
        match self.request_pipe(PipeRequest::Read(ReadPipeRequest { handle, length }))? {
            PipeResponse::Read(response) => Ok(response.data),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    /// Writes bytes to a broker-owned pipe.
    ///
    /// # Panics
    ///
    /// Panics if the broker reports an unrecoverable error or returns a
    /// response that does not match the issued pipe request.
    pub fn write_pipe(
        &mut self,
        handle: ObjectHandle,
        data: &[u8],
    ) -> Result<usize, Channel::Error> {
        match self.request_pipe(PipeRequest::Write(WritePipeRequest {
            handle,
            data: data.to_vec(),
        }))? {
            PipeResponse::Write(response) => Ok(response.written as usize),
            response => panic!("broker returned unexpected pipe response: {response:?}"),
        }
    }

    fn request_pipe(&mut self, request: PipeRequest) -> Result<PipeResponse, Channel::Error> {
        match self.request(BrokerRequest::Pipe(request))? {
            BrokerResponse::Pipe(response) => Ok(response),
            BrokerResponse::Error(error) => Err(BrokerLocalError::Broker(error)),
            response @ (BrokerResponse::ObjectClosed
            | BrokerResponse::Readiness(_)
            | BrokerResponse::Event(_)) => {
                panic!("broker returned unexpected pipe response: {response:?}");
            }
        }
    }
}
