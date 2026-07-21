// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::vec::Vec;

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::channel::LocalControlChannel;
use litebox_broker_protocol::message::{BrokerRequest, BrokerResponse, PipeRequest, PipeResponse};
use litebox_broker_protocol::pipe::{
    CreatePipeRequest, CreatePipeResponse, PIPE_TRANSFER_BUFFER_SIZE, ReadPipeRequest,
    WritePipeRequest,
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
        let response = self.request_pipe(PipeRequest::Create(CreatePipeRequest {
            capacity,
            atomic_write_size,
        }))?;
        let PipeResponse::Create(response) = response else {
            panic!("broker returned unexpected pipe create response: {response:?}");
        };
        Ok(response)
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
        if length as usize > PIPE_TRANSFER_BUFFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        let mut data = Vec::new();
        data.try_reserve_exact(length as usize).map_err(|_| {
            BrokerLocalError::Broker(litebox_broker_protocol::error::ErrorCode::OutOfMemory)
        })?;
        data.resize(length as usize, 0);
        let response = self.request_pipe(PipeRequest::Read(ReadPipeRequest { handle, length }))?;
        let PipeResponse::Read(response) = response else {
            panic!("broker returned unexpected pipe read response: {response:?}");
        };
        assert!(
            response.read <= length,
            "broker returned oversized pipe read"
        );
        let read = response.read as usize;
        data.truncate(read);
        self.shared_memory
            .read(0, &mut data)
            .expect("validated shared pipe read range must be accessible");
        Ok(data)
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
        if data.len() > PIPE_TRANSFER_BUFFER_SIZE {
            return Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::ResourceExhausted,
            ));
        }
        self.shared_memory
            .write(0, data)
            .expect("validated shared pipe write range must be accessible");
        let response = self.request_pipe(PipeRequest::Write(WritePipeRequest {
            handle,
            length: data
                .len()
                .try_into()
                .expect("shared pipe transfer length must fit in u32"),
        }))?;
        let PipeResponse::Write(response) = response else {
            panic!("broker returned unexpected pipe write response: {response:?}");
        };
        let written = response.written as usize;
        assert!(
            written <= data.len(),
            "broker returned oversized shared pipe write"
        );
        Ok(written)
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::convert::Infallible;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use litebox_broker_protocol::BROKER_PROTOCOL_VERSION;
    use litebox_broker_protocol::channel::LocalControlChannel;
    use litebox_broker_protocol::message::{BrokerHandshakeRequest, BrokerHandshakeResponse};
    use litebox_broker_protocol::pipe::{ReadPipeResponse, WritePipeResponse};
    use litebox_broker_protocol::shared_memory::{SharedMemory, SharedMemoryError};

    #[test]
    fn pipe_uses_attached_shared_memory_for_data_operations() {
        let read_handle = ObjectHandle(1);
        let write_handle = ObjectHandle(2);
        let memory = Arc::new(TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE));
        let channel = ScriptedChannel::new([
            BrokerResponse::Pipe(PipeResponse::Create(CreatePipeResponse {
                read_handle,
                write_handle,
            })),
            BrokerResponse::Pipe(PipeResponse::Write(WritePipeResponse { written: 3 })),
            BrokerResponse::Pipe(PipeResponse::Read(ReadPipeResponse { read: 2 })),
            BrokerResponse::ObjectClosed,
        ]);
        let mut local = BrokerLocal::negotiate(channel, |_| Ok(memory.clone())).unwrap();

        local.create_pipe(64, 16).unwrap();
        assert_eq!(local.write_pipe(write_handle, &[1, 2, 3]).unwrap(), 3);
        let mut staged = [0; 3];
        memory.read(0, &mut staged).unwrap();
        assert_eq!(staged, [1, 2, 3]);

        memory.write(0, &[4, 5]).unwrap();
        assert_eq!(local.read_pipe(read_handle, 2).unwrap(), [4, 5]);
        local.close_object(read_handle).unwrap();
        assert_eq!(
            local.channel.sent_requests,
            [
                BrokerRequest::Pipe(PipeRequest::Create(CreatePipeRequest {
                    capacity: 64,
                    atomic_write_size: 16,
                })),
                BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                    handle: write_handle,
                    length: 3,
                })),
                BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest {
                    handle: read_handle,
                    length: 2,
                })),
                BrokerRequest::CloseObject(read_handle),
            ]
        );
    }

    #[test]
    fn pipe_operations_preserve_invalid_handle_errors() {
        let unknown_handle = ObjectHandle(9);
        let channel = ScriptedChannel::new([BrokerResponse::Error(
            litebox_broker_protocol::error::ErrorCode::UnknownObject,
        )]);
        let memory = Arc::new(TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE));
        let mut local = BrokerLocal::negotiate(channel, |_| Ok(memory)).unwrap();

        assert!(matches!(
            local.read_pipe(unknown_handle, 1),
            Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::UnknownObject
            ))
        ));
        assert_eq!(
            local.channel.sent_requests,
            [BrokerRequest::Pipe(PipeRequest::Read(ReadPipeRequest {
                handle: unknown_handle,
                length: 1,
            }))]
        );

        let event_handle = ObjectHandle(10);
        let channel = ScriptedChannel::new([BrokerResponse::Error(
            litebox_broker_protocol::error::ErrorCode::InvalidRights,
        )]);
        let memory = Arc::new(TestSharedMemory::new(PIPE_TRANSFER_BUFFER_SIZE));
        let mut local = BrokerLocal::negotiate(channel, |_| Ok(memory)).unwrap();

        assert!(matches!(
            local.write_pipe(event_handle, &[1]),
            Err(BrokerLocalError::Broker(
                litebox_broker_protocol::error::ErrorCode::InvalidRights
            ))
        ));
        assert_eq!(
            local.channel.sent_requests,
            [BrokerRequest::Pipe(PipeRequest::Write(WritePipeRequest {
                handle: event_handle,
                length: 1,
            }))]
        );
    }

    #[derive(Clone)]
    struct TestSharedMemory(Arc<Mutex<Vec<u8>>>);

    impl TestSharedMemory {
        fn new(length: usize) -> Self {
            Self(Arc::new(Mutex::new(std::vec![0; length])))
        }
    }

    impl SharedMemory for TestSharedMemory {
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }

        fn read(
            &self,
            offset: usize,
            destination: &mut [u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(destination.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let source = memory
                .get(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }

        fn write(
            &self,
            offset: usize,
            source: &[u8],
        ) -> core::result::Result<(), SharedMemoryError> {
            let mut memory = self.0.lock().unwrap();
            let end = offset
                .checked_add(source.len())
                .ok_or(SharedMemoryError::InvalidRange)?;
            let destination = memory
                .get_mut(offset..end)
                .ok_or(SharedMemoryError::InvalidRange)?;
            destination.copy_from_slice(source);
            Ok(())
        }
    }

    struct ScriptedChannel {
        responses: VecDeque<BrokerResponse>,
        sent_requests: Vec<BrokerRequest>,
    }

    impl ScriptedChannel {
        fn new(responses: impl IntoIterator<Item = BrokerResponse>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                sent_requests: Vec::new(),
            }
        }
    }

    impl LocalControlChannel for ScriptedChannel {
        type Error = Infallible;

        fn send_handshake_request(
            &mut self,
            request: &BrokerHandshakeRequest,
        ) -> core::result::Result<(), Self::Error> {
            assert_eq!(request.protocol_version, BROKER_PROTOCOL_VERSION);
            Ok(())
        }

        fn recv_handshake_response(
            &mut self,
        ) -> core::result::Result<Option<BrokerHandshakeResponse>, Self::Error> {
            Ok(Some(BrokerHandshakeResponse::Negotiated {
                broker_protocol_version: BROKER_PROTOCOL_VERSION,
            }))
        }

        fn send_request(
            &mut self,
            request: &BrokerRequest,
        ) -> core::result::Result<(), Self::Error> {
            self.sent_requests.push(request.clone());
            Ok(())
        }

        fn recv_response(&mut self) -> core::result::Result<Option<BrokerResponse>, Self::Error> {
            Ok(self.responses.pop_front())
        }
    }
}
